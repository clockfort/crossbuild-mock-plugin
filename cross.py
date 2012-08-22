# License: GPL2 or later see COPYING
# Copyright (C) 2008, 2009 Red Hat, Inc.
# Written by Mark Salter <msalter@redhat.com>
#
# This is a plugin for mock. It adds support for cross-building RPMs.
#

# python library imports
import fcntl
import glob
import os
import shutil
import time
import subprocess

# our imports
from mock.trace_decorator import decorate, traceLog, getLog
import mock.util

requires_api_version = "1.0"

# plugin entry point
decorate(traceLog())
def init(rootObj, conf):
    CrossBuild(rootObj, conf)

# classes
class CrossBuild(object):
    """Cross-build support."""
    decorate(traceLog())
    def __init__(self, rootObj, conf):
        self.rootObj = rootObj
        rootObj.crossObj = self
        self.log = rootObj.root_log
        self.cross_opts = conf
        self.confdir_path = '/etc/mock-cross'
        self.confdir = rootObj.makeChrootPath(self.confdir_path)
        self.homedir = self.rootObj.makeChrootPath(self.rootObj.homedir)

        # These get set from info in toolconf.<arch>
        self.sysroot_path = None
        self.toolpath = None
        self.triplet = None

        rootObj.addHook("postinit", self._crossPostInitHook)
        rootObj.addHook("prebuild", self._crossPreBuildHook)

    # =============
    # 'Private' API
    # =============
    decorate(traceLog())
    def _crossPostInitHook(self):
        self.log.debug('CrossBuild plugin postinit hook')

        # At this point, the chroot_setup_cmd has been run. Hopefully, packages 
        # installed during that run have placed required config files in /etc/mock-cross/ .

        # start with a clean slate when parsing config files.
        self.ignore_reqs = set([])
        self.sysroot_preload = []
        self.sysroot_preload_grps = []

        # Parse toolconf.<arch>
        toolconf = os.path.join(self.confdir, 'arch', 'toolconf.%s' % self.rootObj.rpmbuild_arch)
        if not os.path.exists(toolconf):
            self.RootError("Toolchain config not found: %s" % toolconf)
        f = None
        try:
            f = open(toolconf, 'r')
            for line in f.read().split('\n'):
                if line.startswith('SYSROOT:'):
                    self.sysroot_path = line[9:].strip()
                    self.sysroot = self.rootObj.makeChrootPath(self.sysroot_path)
                elif line.startswith('TRIPLET:'):
                    self.triplet = line[8:].strip()
                elif line.startswith('PATH:'):
                    self.toolpath = line[5:].strip()
        finally:
            if f:
                f.close()

        if not self.sysroot_path:
            self.RootError("No SYSROOT found in toolchain config.")
        if not self.toolpath:
            self.RootError("No PATH found in toolchain config.")
        if not self.triplet:
            self.RootError("No TRIPLET found in toolchain config.")

        # Create .rpmrc in mock builder homedir.
        src = os.path.join(self.confdir, 'rpmrc')
        dst = os.path.join(self.homedir, '.rpmrc')
        if os.path.exists(src):
            # copy rpmrc file to homedir
            self._write_file(dst, src)
            src = os.path.join(self.confdir, 'arch', 'rpmrc.%s' % self.rootObj.rpmbuild_arch)
            if os.path.exists(src):
                self._write_file(dst, src, append=True)

        # Append to .rpmmacros in mock builder homedir.
        # mock always writes out fresh copy at init time, so we append to that
        src = os.path.join(self.confdir, 'rpmmacros')
        dst = os.path.join(self.homedir, '.rpmmacros')
        if os.path.exists(src):
            self._write_file(dst, src, append=True)
        src = os.path.join(self.confdir, 'arch', 'rpmmacros.%s' % self.rootObj.rpmbuild_arch)
        if os.path.exists(src):
            self._write_file(dst, src, append=True)

        self._write_buf(dst, "%%_sysroot %s\n%%_tool_triplet %s\n%%_arch %s\n"
                         % (self.sysroot_path, self.triplet, self.rootObj.rpmbuild_arch),
                        append=True)

        # setup toolchain path
        self._write_buf(self.rootObj.makeChrootPath('/etc/profile.d/crosstoolpath.sh'),
                        "PATH=${PATH}:%s\nexport PATH\n" % self.toolpath)

        # setup sysroot rpmdb
        rpmpath = os.path.join(self.sysroot, 'var', 'lib', 'rpm')
        if not os.path.exists(rpmpath):
            mock.util.mkdirIfAbsent(rpmpath)
            self._sysroot_rpm("--initdb")

        # setup sysroot yum
        mock.util.mkdirIfAbsent(os.path.join(self.sysroot, 'var', 'cache', 'yum'))
        mock.util.mkdirIfAbsent(os.path.join(self.sysroot, 'etc'))
        self._write_buf(os.path.join(self.sysroot, 'etc', 'yum.conf'), self.cross_opts['yum.conf'])
                        
        # Read in sysroot preload list.
        # These are target arch packages which should be installed in the target sysroot
        # on every build. Things like glibc. But only if they exist in the repo. Packages
        # in this list which do not exist in the repo should be ignored. Also, some of
        # these pacakges need to be treated as a group where all must be installed if
        # any are installed.
        #
        # Blank lines or lines starting with # are ignored.
        # Remaining lines are packages to preload in sysroot. If a line contains more
        # than one package name seperated by commas, then those packages are treated
        # as a group.
        #
        preload = os.path.join(self.confdir, 'sysroot-preload.conf')
        if os.path.exists(preload):
            f = None
            try:
                f = open(preload, 'r')
                for l in f.read().split('\n'):
                    line = l.strip()
                    if len(line) and line[0] != '#':
                        grp = line.split(',')
                        self.sysroot_preload.extend(grp)
                        if len(grp) > 1:
                            self.sysroot_preload_grps.append(grp)
            finally:
                if f:
                    f.close()
        else:
            self.log.debug('sysroot-preload.conf not found.')            

        # Read in ignore list.
        # These are packages which don't really need to be installed in the target sysroot.
        # Mostly packages which contain no libraries/headers needed for crossbuilding.
        #
        # Blank lines or lines starting with # are dropped
        # Remaining lines are names of packages to ignore (one per line).
        ignore = os.path.join(self.confdir, 'sysroot-ignore.conf')
        if os.path.exists(ignore):
            f = None
            try:
                f = open(ignore, 'r')
                for l in f.read().split('\n'):
                    line = l.strip()
                    if len(line) and line[0] != '#':
                        self.ignore_reqs |= set([ line ])
            finally:
                if f:
                    f.close()
        else:
            self.log.debug('sysroot-ignore.conf not found.')            


    decorate(traceLog())
    def _crossPreBuildHook(self):
        self.log.debug('Installing cross BuildReqs into sysroot')

        # At this point, native build deps have already been resolved in the chroot.
        # Now we need to solve target arch deps for the toolchain sysroot.

        srpmPath = os.path.join(self.rootObj.builddir, 'SRPMS')
        chrootSrpmFile = glob.glob("%s/*.src.rpm" % self.rootObj.makeChrootPath(srpmPath))
        if len(chrootSrpmFile) != 1:
            raise mock.exception.PkgError, "Didnt find single rebuilt srpm."
        chrootSrpmFile = chrootSrpmFile[0]
        srpmFilename = os.path.basename(chrootSrpmFile)
        srpmFile = os.path.join(srpmPath, srpmFilename)

        try:
            self.rootObj.uidManager.becomeUser(0, 0)

            # Some packages build intermediate tools which are then used later in the
            # package build process. When crossbuilding, we need versions of those tools
            # which can run on the build host. The following handles the case where a
            # a suitable native version of the build tool can be found in the build repo.
            depfile = os.path.join(self.confdir_path, 'pkgdeps.sh')
            if os.path.exists(self.rootObj.makeChrootPath(depfile)):
                deps = self.rootObj.doChroot([ '/bin/sh', depfile, srpmFile ],
                                             shell=False, returnOutput=1,
                                             uid=self.rootObj.chrootuid,
                                             gid=self.rootObj.chrootgid)
                pkgs = ""
                for line in deps.split('\n'):
                    l = line.strip()
                    if len(l) > 0:
                        pkgs = pkgs + " " + l
                pkgs = pkgs.strip()
                if len(pkgs) > 0:
                    self.rootObj._yum('install %s' % pkgs, returnOutput=1)

            # Find versions of packages installed in chroot.
            output = self._chroot_rpm('-qa --qf "%{NAME} %{VERSION}\\n"', returnOutput=1)
            self.chroot_pkgs = {}
            for pkg in output.split('\n'):
                if len(pkg) > 0:
                    nv = pkg.split()
                    if len(nv) != 2:
                        if len(nv) > 2:
                            self.log.debug("Spaces not allowed in names or versions")
                        else:
                            self.log.debug("missing version: %s" % pkg)
                        continue
                    self.chroot_pkgs[nv[0]] = nv[1]

            #
            # Figure out which packages we need to install in the sysroot.
            #
            to_preload = []
            for pkg in self.sysroot_preload:
                if self.chroot_pkgs.has_key(pkg):
                    to_preload.append(pkg)

            # parse srpm header for BuildRequires
            # and add preload packages to this list
            srpm_reqs = []
            for hdr in mock.util.yieldSrpmHeaders([ chrootSrpmFile ], plainRpmOk=1):
                # get text buildreqs
                a = mock.util.requiresTextFromHdr(hdr)
                b = mock.util.getAddtlReqs(hdr, self.rootObj.more_buildreqs)
                srpm_reqs.extend(mock.util.uniqReqs(a, b, to_preload))

            # So now we have a starting list of possible packages to install in sysroot
            # Figure out which ones to install and which to ignore.

            to_install=[]
            to_ignore=[]

            if len(srpm_reqs) > 0:
                # We need to resolve some build requirements in sysroot
                arg_string = ""
                for req in srpm_reqs:
                    arg_string += " '%s'" % req

                self.log.debug("BuildRequires: " + arg_string)

                # ask yum to resolve the deps using target repo.
                found_deps, missing_deps = self._sysroot_resolvedep(arg_string)

                # for missing deps not in the preload list, find
                # out the packages which provide them to the chroot.
                if len(missing_deps) > 0:
                    arg_string = ""
                    for dep in missing_deps:
                        depname = dep.split()[0]
                        if depname not in to_preload:
                            arg_string += " '%s'" % dep

                    if arg_string != "":
                        _found, _missing = self._chroot_resolvedep(arg_string)

                        # we really shouldn't get any missing deps here or we would have
                        # had an error earlier when mock was solving deps for the chroot
                        bad_deps = ""
                        for dep in _missing:
                            depname = dep.split()[0]
                            if depname in self.ignore_reqs:
                                to_ignore.append(depname)
                            else:
                                bad_deps += " '%s'" % dep

                        for dep in _found:
                            if dep in self.ignore_reqs:
                                to_ignore.append(dep)
                            elif dep not in to_preload:
                                bad_deps += " '%s'" % dep
                        
                        # error on any unresolved dependencies
                        if bad_deps != "":
                            self.log.debug("Bad cross build req(s): %s" % bad_deps)
                            raise mock.exception.BuildError, "Bad cross build req(s): %s. Exiting." % bad_deps
                    
                for dep in found_deps:
                    if dep in self.ignore_reqs:
                        to_ignore.append(dep)
                    else:
                        to_install.append(dep)

                # finally, check install list to make sure all or no packages
                # in a preload group are installed
                for grp in self.sysroot_preload_grps:
                    all_in = False
                    if grp[0] in to_install:
                        all_in = True
                        for g in grp:
                            if g not in to_install:
                                all_in = False
                                break
                    if not all_in:
                        # remove from list
                        for g in grp:
                            if g in to_install:
                                to_install.remove(g)

            # add in packages from ignore list which exist in chroot
            # and are not in to_install.
            for p in self.ignore_reqs:
                if self.chroot_pkgs.has_key(p):
                    if p not in to_ignore:
                        to_ignore.append(p)

            #
            # generate and install/update a package of dummy provides for the sysroot.
            #
            
            specfile = self._create_provides_spec(to_ignore)
            # get rid of rootdir prefix
            chrootspec = specfile.replace(self.rootObj.makeChrootPath(), '')

            # Build dummy provides package.
            self.rootObj.doChroot(
                ["bash", "--login", "-c", 'rpmbuild -bb --target %s --nodeps %s' % (self.rootObj.rpmbuild_arch, chrootspec)],
                shell=False,
                logger=self.rootObj.build_log,
                uid=self.rootObj.chrootuid,
                gid=self.rootObj.chrootgid,
                raiseExc=False
                )
            
            # Install/update dummy provides in sysroot.
            providesRpmFile = glob.glob("%s/%s/RPMS/mock-cross-provides-*rpm" % (self.rootObj.makeChrootPath(), self.rootObj.builddir))
            if len(providesRpmFile) != 1:
                raise mock.exception.PkgError, "Didnt find dummy provides srpm." 
            self._sysroot_rpm("--force --nodeps --noscripts --excludedocs --ignorearch -i %s" % providesRpmFile[0])
            os.remove(providesRpmFile[0])
            os.remove(specfile)

            # install any needed packages into sysroot
            if len(to_install) > 0:
                self._sysroot_yum('install %s' % " ".join(to_install))

            #
            # Take care of chroot/sysroot "fixups"
            #

            # Fix soft links to absolute paths in sysroot by making them path relative.
            for root, dirs, files in os.walk(self.sysroot):
                for f in files:
                    src = "%s/%s" % (root, f)
                    if os.path.islink(src):
                        dst = os.readlink(src)
                        if os.path.isabs(dst):
                            # strip out sysroot path
                            abs = src[len(self.sysroot):]

                            # Find the common prefix of both strings (must end in a '/')
                            prefix = os.path.commonprefix([abs, dst])
                            if prefix[-1] != '/':
                                last_slash = prefix.rfind('/') + 1
                                prefix = prefix[:last_slash]

                            # Convert from absolute to relative
                            slashes = abs[len(prefix):].count('/')
                            new_dst = ('../' * slashes) + dst[len(prefix):]

                            self.log.debug("Fixing absolute symlink: %s -> %s (%s)" % (abs, dst, new_dst))
                            os.unlink(src)
                            os.symlink(new_dst, src)

                            
            # run sysroot-post.sh in the chroot
            postfile = os.path.join(self.confdir_path, 'sysroot-post.sh')
            if os.path.exists(self.rootObj.makeChrootPath(postfile)):
                cmd = [ '/bin/sh', postfile,
                        srpmFilename,
                        self.sysroot_path,
                        self.rootObj.builddir,
                        self.confdir_path,
                        self.triplet,
                        self.toolpath
                      ]
                self.rootObj.doChroot(cmd, shell=False)
            else:
                self.log.debug('sysroot-post.sh not found.')            

        finally:
            self.rootObj.uidManager.restorePrivs()

    decorate(traceLog())
    def _parse_resolvedep(self, lines):
        """parse output from yum resolvedep"""
        notfound=[]
        found=[]
        for line in lines.split('\n'):
            if line.lower().find('no package found for') != -1:
                dep = line[21:]
                notfound.append(dep)
            else:
                # Look for form:  '[0-9]+:name-ver-rel.arch'
                dep = line
                i = dep.find(':')
                if i >= 0:
                    dep = dep[i+1:]
                i = dep.rfind('-')
                if i > 0:
                    dep = dep[:i]
                    i = dep.rfind('-')
                    if i > 0:
                        dep = dep[:i].strip()
                        if dep not in found:
                            found.append(dep)
        for dep in notfound:
            parts = dep.split()
            if len(parts) > 1:
                if parts[0] in found:
                    found.remove(parts[0])
        return ( found, notfound )

    decorate(traceLog())
    def _sysroot_resolvedep(self, deps):
        """Resolve deps using sysroot repo"""
        lines = self._sysroot_yum('-q resolvedep %s' % deps, returnOutput=1)
        return self._parse_resolvedep(lines)

    decorate(traceLog())
    def _chroot_resolvedep(self, deps):
        """Resolve deps using chroot repo"""
        lines = self.rootObj._yum('-q resolvedep %s' % deps, returnOutput=1)
        return self._parse_resolvedep(lines)

    decorate(traceLog())
    def _sysroot_yum(self, cmd, returnOutput=0):
        """use yum to install packages/package groups into the sysroot"""
        # mock-helper yum --installroot=rootdir cmd
        cmdOpts = ""
        if not self.rootObj.online:
            cmdOpts = "-C"

        cmd = '%s --installarch=%s --installroot %s %s %s' % (self.rootObj.yum_path, self.rootObj.rpmbuild_arch, self.sysroot, cmdOpts, cmd)
        self.log.debug(cmd)
        output = ""
        try:
            output = mock.util.do(cmd, returnOutput=returnOutput, shell=True)
            return output
        except mock.exception.Error, e:
            raise mock.exception.YumError, str(e)

    decorate(traceLog())
    def _sysroot_rpm(self, command, returnOutput=0):

        cmd = "/bin/rpm --root %s %s" % (self.sysroot, command)
        output = ""
        try:
            output = mock.util.do(cmd, shell=True, returnOutput=returnOutput)
            return output
        except mock.exception.Error, e:
            raise mock.exception.YumError, str(e)

    decorate(traceLog())
    def _chroot_rpm(self, command, returnOutput=0):
        cmd = "/bin/rpm --root %s %s" %  (self.rootObj.makeChrootPath(), command)
        output = ""
        try:
            output = self.do_quietly(cmd, shell=True, returnOutput=returnOutput)
            return output
        except mock.exception.Error, e:
            raise mock.exception.YumError, str(e)


    decorate(traceLog())
    def _write_file(self, dst, src, append=False):
        # copy rpmrc file to homedir
        fsrc = None
        fdst = None
        try:
            fsrc = open(src, 'r')
            if append:
                fdst = open(dst, 'a')
            else:
                fdst = open(dst, 'w')
            shutil.copyfileobj(fsrc, fdst)
        finally:
            if fdst:
                fdst.close()
            if fsrc:
                fsrc.close()

    decorate(traceLog())
    def _write_buf(self, dst, buf, append=False):
        # copy rpmrc file to homedir
        fdst = None
        try:
            if append:
                fdst = open(dst, 'a')
            else:
                fdst = open(dst, 'w')
            fdst.write(buf)
        finally:
            if fdst:
                fdst.close()

    decorate(traceLog())
    def RootError(self, msg):
        self.log.debug(msg)
        raise mock.exception.RootError, msg

    # logger =
    # output = [1|0]
    # chrootPath
    #
    # A "do" command which logs the command being executed, but not the command output.
    #
    decorate(traceLog())
    def do_quietly(self, command, shell=False, chrootPath=None, cwd=None, timeout=0, raiseExc=True, returnOutput=0, uid=None, gid=None, personality=None, *args, **kargs):

        logger = kargs.get("logger", getLog())
        output = ""
        start = time.time()
        preexec = mock.util.ChildPreExec(personality, chrootPath, cwd, uid, gid)
        try:
            child = None
            logger.debug("Executing command: %s" % command)
            child = subprocess.Popen(
                command, 
                shell=shell,
                bufsize=0, close_fds=True, 
                stdin=open("/dev/null", "r"), 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn = preexec,
                )

            # use select() to poll for output so we dont block
            output = mock.util.logOutput([child.stdout, child.stderr], 
                                         None, returnOutput, start, timeout)

        except:
            # kill children if they arent done
            if child is not None and child.returncode is None:
                os.killpg(child.pid, 9)
            try:
                if child is not None:
                    os.waitpid(child.pid, 0)
            except: 
                pass
            raise

        # wait until child is done, kill it if it passes timeout
        niceExit=1
        while child.poll() is None:
            if (time.time() - start)>timeout and timeout!=0:
                niceExit=0
                os.killpg(child.pid, 15)
            if (time.time() - start)>(timeout+1) and timeout!=0:
                niceExit=0
                os.killpg(child.pid, 9)

        if not niceExit:
            raise commandTimeoutExpired, ("Timeout(%s) expired for command:\n # %s\n%s" % (timeout, command, output))

        logger.debug("Child returncode was: %s" % str(child.returncode))
        if raiseExc and child.returncode:
            if returnOutput:
                raise mock.exception.Error, ("Command failed: \n # %s\n%s" % (command, output), child.returncode)
            else:
                raise mock.exception.Error, ("Command failed. See logs for output.\n # %s" % (command,), child.returncode)

        return output

    decorate(traceLog())
    def _create_provides_spec(self, pkgs_to_ignore):
        """create specfile used to create a dummy sysroot package for handling ignored deps"""

        arg_str = " ".join(pkgs_to_ignore)

        # create provides list
        output = self._chroot_rpm('-q --provides %s' % arg_str, returnOutput=1)
        _provides = output.split('\n')

        # create file/dir list
        _dirs = []
        _files = []
        output = self._chroot_rpm('-ql %s' % arg_str, returnOutput=1)
        for line in output.split('\n'):
            if line.find('/bin/') >= 0 or line.find('/sbin/') >= 0:
                _files.append(line)
                d = os.path.dirname(line)
                if d not in _dirs:
                    _dirs.append(d)
            
        specfile = self.rootObj.makeChrootPath(self.rootObj.builddir, "SPECS", "mock-cross-provides.spec")
        specfd = None
        try:
            specfd = open(specfile, 'w+')
            specfd.write("""
Name:		mock-cross-provides
Version:	1.0
Release:	1
Summary:	Generate dummy Provides/files in cross-target sysroot.
Group:		System Environment
License:	GPL
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root

""")

            for p in _provides:
                p = p.strip()
                if len(p) > 0:
                    specfd.write("Provides: %s\n" % p)

            specfd.write("""

%description
%{summary}

%prep
# nothing

%build
# nothing

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc
touch $RPM_BUILD_ROOT/etc/dummy-provides
""")                       

            for d in _dirs:
                d = d.strip()
                if len(d) > 0:
                    specfd.write("mkdir -p $RPM_BUILD_ROOT%s\n" % d)

            for f in _files:
                f = f.strip()
                if len(f) > 0:
                    specfd.write("touch $RPM_BUILD_ROOT%s\n" % f)
                
            specfd.write("""

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/etc/dummy-provides
""")
            for f in _files:
                f = f.strip()
                if len(f) > 0:
                    specfd.write("%s\n" % f)

            specfd.write("""

%changelog
* Sat Feb 14 2009 mock cross <mock>
- Generated by mock-cross.
""")

        finally:
            if specfd:
                specfd.close()
        
        return specfile
        
