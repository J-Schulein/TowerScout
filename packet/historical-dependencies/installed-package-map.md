<!-- towerscout-cdcai-rehearsal-v1:installed-package-map -->

# Audit appendix: installed package/source mapping

Both preserved image inventories contain the same 147 Debian binary-package identities, mapping to 95 source-package/version sets. Python has 71 CPU / 89 CUDA distributions and 91 distinct name/version pairs. Missing PyPI sdists do not themselves establish a license violation or a requirement to publish proprietary source. Preserve actual license and build evidence; the native appendix exposes the separately hashed ELF payloads.

CPU local image ID: `sha256:612d4124b917e796ac20e22f14b758cd9aeab4e14ed5ec21b2da29c047864230`.

CUDA local image ID: `sha256:21deddad166329287b42fc50c7d8c1b9eabf29215967c44e6d2604ea541b5de8`.

These are local image/configuration identities, not final registry manifests.

<details>
<summary>Debian binary-to-source map</summary>

```tsv
binary_package	binary_version	source_package	source_version
adduser	3.134	adduser	3.134
apt	2.6.1	apt	2.6.1
base-files	12.4+deb12u15	base-files	12.4+deb12u15
base-passwd	3.6.1	base-passwd	3.6.1
bash	5.2.15-2+b13	bash	5.2.15-2
bsdutils	1:2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
ca-certificates	20250419~deb12u2	ca-certificates	20250419~deb12u2
coreutils	9.1-1	coreutils	9.1-1
dash	0.5.12-2	dash	0.5.12-2
debconf	1.5.82	debconf	1.5.82
debian-archive-keyring	2023.3+deb12u2	debian-archive-keyring	2023.3+deb12u2
debianutils	5.7-0.5~deb12u1	debianutils	5.7-0.5~deb12u1
diffutils	1:3.8-4	diffutils	1:3.8-4
dpkg	1.21.23	dpkg	1.21.23
e2fsprogs	1.47.0-2+b2	e2fsprogs	1.47.0-2
findutils	4.9.0-4	findutils	4.9.0-4
gcc-12-base:amd64	12.2.0-14+deb12u1	gcc-12	12.2.0-14+deb12u1
gpgv	2.2.40-1.1+deb12u2	gnupg2	2.2.40-1.1+deb12u2
grep	3.8-5	grep	3.8-5
gzip	1.12-1	gzip	1.12-1
hostname	3.23+nmu1	hostname	3.23+nmu1
init-system-helpers	1.65.2+deb12u1	init-system-helpers	1.65.2+deb12u1
libacl1:amd64	2.3.1-3	acl	2.3.1-3
libapt-pkg6.0:amd64	2.6.1	apt	2.6.1
libattr1:amd64	1:2.5.1-4	attr	1:2.5.1-4
libaudit-common	1:3.0.9-1	audit	1:3.0.9-1
libaudit1:amd64	1:3.0.9-1	audit	1:3.0.9-1
libblkid1:amd64	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
libbsd0:amd64	0.11.7-2	libbsd	0.11.7-2
libbz2-1.0:amd64	1.0.8-5+b1	bzip2	1.0.8-5
libc-bin	2.36-9+deb12u14	glibc	2.36-9+deb12u14
libc6:amd64	2.36-9+deb12u14	glibc	2.36-9+deb12u14
libcap-ng0:amd64	0.8.3-1+b3	libcap-ng	0.8.3-1
libcap2:amd64	1:2.66-4+deb12u3+b1	libcap2	1:2.66-4+deb12u3
libcom-err2:amd64	1.47.0-2+b2	e2fsprogs	1.47.0-2
libcrypt1:amd64	1:4.4.33-2	libxcrypt	1:4.4.33-2
libdb5.3:amd64	5.3.28+dfsg2-1	db5.3	5.3.28+dfsg2-1
libdebconfclient0:amd64	0.270	cdebconf	0.270
libdrm-amdgpu1:amd64	2.4.114-1+b1	libdrm	2.4.114-1
libdrm-common	2.4.114-1	libdrm	2.4.114-1
libdrm-intel1:amd64	2.4.114-1+b1	libdrm	2.4.114-1
libdrm-nouveau2:amd64	2.4.114-1+b1	libdrm	2.4.114-1
libdrm-radeon1:amd64	2.4.114-1+b1	libdrm	2.4.114-1
libdrm2:amd64	2.4.114-1+b1	libdrm	2.4.114-1
libedit2:amd64	3.1-20221030-2	libedit	3.1-20221030-2
libelf1:amd64	0.188-2.1	elfutils	0.188-2.1
libexpat1:amd64	2.5.0-1+deb12u5	expat	2.5.0-1+deb12u5
libext2fs2:amd64	1.47.0-2+b2	e2fsprogs	1.47.0-2
libffi8:amd64	3.4.4-1	libffi	3.4.4-1
libgcc-s1:amd64	12.2.0-14+deb12u1	gcc-12	12.2.0-14+deb12u1
libgcrypt20:amd64	1.10.1-3+deb12u1	libgcrypt20	1.10.1-3+deb12u1
libgdbm6:amd64	1.23-3	gdbm	1.23-3
libgl1:amd64	1.6.0-1	libglvnd	1.6.0-1
libgl1-mesa-dri:amd64	22.3.6-1+deb12u2	mesa	22.3.6-1+deb12u2
libglapi-mesa:amd64	22.3.6-1+deb12u2	mesa	22.3.6-1+deb12u2
libglib2.0-0:amd64	2.74.6-2+deb12u9	glib2.0	2.74.6-2+deb12u9
libglvnd0:amd64	1.6.0-1	libglvnd	1.6.0-1
libglx-mesa0:amd64	22.3.6-1+deb12u2	mesa	22.3.6-1+deb12u2
libglx0:amd64	1.6.0-1	libglvnd	1.6.0-1
libgmp10:amd64	2:6.2.1+dfsg1-1.1	gmp	2:6.2.1+dfsg1-1.1
libgnutls30:amd64	3.7.9-2+deb12u7	gnutls28	3.7.9-2+deb12u7
libgpg-error0:amd64	1.46-1	libgpg-error	1.46-1
libgssapi-krb5-2:amd64	1.20.1-2+deb12u5	krb5	1.20.1-2+deb12u5
libhogweed6:amd64	3.8.1-2	nettle	3.8.1-2
libicu72:amd64	72.1-3+deb12u1	icu	72.1-3+deb12u1
libidn2-0:amd64	2.3.3-1+b1	libidn2	2.3.3-1
libk5crypto3:amd64	1.20.1-2+deb12u5	krb5	1.20.1-2+deb12u5
libkeyutils1:amd64	1.6.3-2	keyutils	1.6.3-2
libkrb5-3:amd64	1.20.1-2+deb12u5	krb5	1.20.1-2+deb12u5
libkrb5support0:amd64	1.20.1-2+deb12u5	krb5	1.20.1-2+deb12u5
libllvm15:amd64	1:15.0.6-4+b1	llvm-toolchain-15	1:15.0.6-4
liblz4-1:amd64	1.9.4-1	lz4	1.9.4-1
liblzma5:amd64	5.4.1-1+deb12u2	xz-utils	5.4.1-1+deb12u2
libmd0:amd64	1.0.4-2	libmd	1.0.4-2
libmount1:amd64	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
libncursesw6:amd64	6.4-4	ncurses	6.4-4
libnettle8:amd64	3.8.1-2	nettle	3.8.1-2
libnsl2:amd64	1.3.0-2	libnsl	1.3.0-2
libp11-kit0:amd64	0.24.1-2	p11-kit	0.24.1-2
libpam-modules:amd64	1.5.2-6+deb12u2	pam	1.5.2-6+deb12u2
libpam-modules-bin	1.5.2-6+deb12u2	pam	1.5.2-6+deb12u2
libpam-runtime	1.5.2-6+deb12u2	pam	1.5.2-6+deb12u2
libpam0g:amd64	1.5.2-6+deb12u2	pam	1.5.2-6+deb12u2
libpciaccess0:amd64	0.17-2	libpciaccess	0.17-2
libpcre2-8-0:amd64	10.42-1+deb12u2	pcre2	10.42-1+deb12u2
libreadline8:amd64	8.2-1.3	readline	8.2-1.3
libseccomp2:amd64	2.5.4-1+deb12u1	libseccomp	2.5.4-1+deb12u1
libselinux1:amd64	3.4-1+b6	libselinux	3.4-1
libsemanage-common	3.4-1	libsemanage	3.4-1
libsemanage2:amd64	3.4-1+b5	libsemanage	3.4-1
libsensors-config	1:3.6.0-7.1	lm-sensors	1:3.6.0-7.1
libsensors5:amd64	1:3.6.0-7.1	lm-sensors	1:3.6.0-7.1
libsepol2:amd64	3.4-2.1	libsepol	3.4-2.1
libsmartcols1:amd64	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
libsqlite3-0:amd64	3.40.1-2+deb12u2	sqlite3	3.40.1-2+deb12u2
libss2:amd64	1.47.0-2+b2	e2fsprogs	1.47.0-2
libssl3:amd64	3.0.22-1~deb12u1	openssl	3.0.22-1~deb12u1
libstdc++6:amd64	12.2.0-14+deb12u1	gcc-12	12.2.0-14+deb12u1
libsystemd0:amd64	252.39-1~deb12u2	systemd	252.39-1~deb12u2
libtasn1-6:amd64	4.19.0-2+deb12u1	libtasn1-6	4.19.0-2+deb12u1
libtinfo6:amd64	6.4-4	ncurses	6.4-4
libtirpc-common	1.3.3+ds-1	libtirpc	1.3.3+ds-1
libtirpc3:amd64	1.3.3+ds-1	libtirpc	1.3.3+ds-1
libudev1:amd64	252.39-1~deb12u2	systemd	252.39-1~deb12u2
libunistring2:amd64	1.0-2	libunistring	1.0-2
libuuid1:amd64	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
libx11-6:amd64	2:1.8.4-2+deb12u2	libx11	2:1.8.4-2+deb12u2
libx11-data	2:1.8.4-2+deb12u2	libx11	2:1.8.4-2+deb12u2
libx11-xcb1:amd64	2:1.8.4-2+deb12u2	libx11	2:1.8.4-2+deb12u2
libxau6:amd64	1:1.0.9-1	libxau	1:1.0.9-1
libxcb-dri2-0:amd64	1.15-1	libxcb	1.15-1
libxcb-dri3-0:amd64	1.15-1	libxcb	1.15-1
libxcb-glx0:amd64	1.15-1	libxcb	1.15-1
libxcb-present0:amd64	1.15-1	libxcb	1.15-1
libxcb-randr0:amd64	1.15-1	libxcb	1.15-1
libxcb-shm0:amd64	1.15-1	libxcb	1.15-1
libxcb-sync1:amd64	1.15-1	libxcb	1.15-1
libxcb-xfixes0:amd64	1.15-1	libxcb	1.15-1
libxcb1:amd64	1.15-1	libxcb	1.15-1
libxdmcp6:amd64	1:1.1.2-3	libxdmcp	1:1.1.2-3
libxext6:amd64	2:1.3.4-1+b1	libxext	2:1.3.4-1
libxfixes3:amd64	1:6.0.0-2	libxfixes	1:6.0.0-2
libxml2:amd64	2.9.14+dfsg-1.3~deb12u6	libxml2	2.9.14+dfsg-1.3~deb12u6
libxshmfence1:amd64	1.3-1	libxshmfence	1.3-1
libxxf86vm1:amd64	1:1.1.4-1+b2	libxxf86vm	1:1.1.4-1
libxxhash0:amd64	0.8.1-1	xxhash	0.8.1-1
libz3-4:amd64	4.8.12-3.1	z3	4.8.12-3.1
libzstd1:amd64	1.5.4+dfsg2-5	libzstd	1.5.4+dfsg2-5
login	1:4.13+dfsg1-1+deb12u2	shadow	1:4.13+dfsg1-1+deb12u2
logsave	1.47.0-2+b2	e2fsprogs	1.47.0-2
mawk	1.3.4.20200120-3.1	mawk	1.3.4.20200120-3.1
mount	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
ncurses-base	6.4-4	ncurses	6.4-4
ncurses-bin	6.4-4	ncurses	6.4-4
netbase	6.4	netbase	6.4
openssl	3.0.22-1~deb12u1	openssl	3.0.22-1~deb12u1
passwd	1:4.13+dfsg1-1+deb12u2	shadow	1:4.13+dfsg1-1+deb12u2
perl-base	5.36.0-7+deb12u4	perl	5.36.0-7+deb12u4
readline-common	8.2-1.3	readline	8.2-1.3
sed	4.9-1+deb12u1	sed	4.9-1+deb12u1
sysvinit-utils	3.06-4	sysvinit	3.06-4
tar	1.34+dfsg-1.2+deb12u1	tar	1.34+dfsg-1.2+deb12u1
tzdata	2026c-0+deb12u1	tzdata	2026c-0+deb12u1
usr-is-merged	37~deb12u1	usrmerge	37~deb12u1
util-linux	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
util-linux-extra	2.38.1-5+deb12u3	util-linux	2.38.1-5+deb12u3
zlib1g:amd64	1:1.2.13.dfsg-1	zlib	1:1.2.13.dfsg-1
```

</details>

<details>
<summary>Python distributions and staged source status</summary>

```tsv
flavors	distribution	version	status
cpu,cuda	Flask	3.1.3	exact-version sdist staged; native coverage separate
cpu,cuda	Flask-Session	0.6.0	exact-version sdist staged; native coverage separate
cpu,cuda	Jinja2	3.1.6	exact-version sdist staged; native coverage separate
cpu,cuda	MarkupSafe	3.0.3	exact-version sdist staged; native coverage separate
cpu,cuda	PyYAML	6.0.3	exact-version sdist staged; native coverage separate
cpu,cuda	Werkzeug	3.1.9	exact-version sdist staged; native coverage separate
cpu,cuda	aiofiles	23.2.1	exact-version sdist staged; native coverage separate
cpu,cuda	aiohappyeyeballs	2.7.1	exact-version sdist staged; native coverage separate
cpu,cuda	aiohttp	3.14.4	exact-version sdist staged; native coverage separate
cpu,cuda	aiosignal	1.4.0	exact-version sdist staged; native coverage separate
cpu,cuda	attrs	26.1.0	exact-version sdist staged; native coverage separate
cpu,cuda	blinker	1.9.0	exact-version sdist staged; native coverage separate
cpu,cuda	cachelib	0.17.0	exact-version sdist staged; native coverage separate
cpu,cuda	certifi	2026.10.19	exact-version sdist staged; native coverage separate
cpu,cuda	cffi	2.1.1	exact-version sdist staged; native coverage separate
cpu,cuda	charset-normalizer	3.5.2	exact-version sdist staged; native coverage separate
cpu,cuda	click	8.5.0	exact-version sdist staged; native coverage separate
cpu,cuda	click-plugins	1.1.1.2	exact-version sdist staged; native coverage separate
cpu,cuda	cligj	0.7.2	exact-version sdist staged; native coverage separate
cpu,cuda	contourpy	1.3.3	exact-version sdist staged; native coverage separate
cpu,cuda	cryptography	50.0.0	exact-version sdist staged; native coverage separate
cuda	cuda-bindings	12.9.4	upstream source/build or redistribution mapping required
cuda	cuda-pathfinder	1.6.0	upstream source/build or redistribution mapping required
cpu,cuda	cycler	0.12.1	exact-version sdist staged; native coverage separate
cpu,cuda	efficientnet_pytorch	0.7.1	exact-version sdist staged; native coverage separate
cpu,cuda	filelock	3.32.3	exact-version sdist staged; native coverage separate
cpu,cuda	fiona	1.10.1	exact-version sdist staged; native coverage separate
cpu,cuda	fonttools	4.67.0	exact-version sdist staged; native coverage separate
cpu,cuda	frozenlist	1.8.0	exact-version sdist staged; native coverage separate
cpu,cuda	fsspec	2026.7.0	exact-version sdist staged; native coverage separate
cpu,cuda	geopandas	1.1.2	exact-version sdist staged; native coverage separate
cpu,cuda	idna	3.20	exact-version sdist staged; native coverage separate
cpu,cuda	itsdangerous	2.2.0	exact-version sdist staged; native coverage separate
cpu,cuda	kiwisolver	1.5.1	exact-version sdist staged; native coverage separate
cpu,cuda	matplotlib	3.11.2	exact-version sdist staged; native coverage separate
cpu,cuda	mpmath	1.3.0	exact-version sdist staged; native coverage separate
cpu,cuda	multidict	6.9.1	exact-version sdist staged; native coverage separate
cpu,cuda	networkx	3.6.1	exact-version sdist staged; native coverage separate
cpu,cuda	numpy	1.26.4	exact-version sdist staged; native coverage separate
cuda	nvidia-cublas-cu12	12.8.4.1	upstream source/build or redistribution mapping required
cuda	nvidia-cuda-cupti-cu12	12.8.90	upstream source/build or redistribution mapping required
cuda	nvidia-cuda-nvrtc-cu12	12.8.93	upstream source/build or redistribution mapping required
cuda	nvidia-cuda-runtime-cu12	12.8.90	upstream source/build or redistribution mapping required
cuda	nvidia-cudnn-cu12	9.10.2.21	upstream source/build or redistribution mapping required
cuda	nvidia-cufft-cu12	11.3.3.83	upstream source/build or redistribution mapping required
cuda	nvidia-cufile-cu12	1.13.1.3	upstream source/build or redistribution mapping required
cuda	nvidia-curand-cu12	10.3.9.90	upstream source/build or redistribution mapping required
cuda	nvidia-cusolver-cu12	11.7.3.90	upstream source/build or redistribution mapping required
cuda	nvidia-cusparse-cu12	12.5.8.93	upstream source/build or redistribution mapping required
cuda	nvidia-cusparselt-cu12	0.7.1	upstream source/build or redistribution mapping required
cuda	nvidia-nccl-cu12	2.27.5	upstream source/build or redistribution mapping required
cuda	nvidia-nvjitlink-cu12	12.8.93	upstream source/build or redistribution mapping required
cuda	nvidia-nvshmem-cu12	3.4.5	upstream source/build or redistribution mapping required
cuda	nvidia-nvtx-cu12	12.8.90	upstream source/build or redistribution mapping required
cpu,cuda	opencv-python	4.9.0.80	exact-version sdist staged; native coverage separate
cpu,cuda	packaging	25.0	exact-version sdist staged; native coverage separate
cpu,cuda	pandas	2.3.3	exact-version sdist staged; native coverage separate
cpu,cuda	pillow	13.0.0	exact-version sdist staged; native coverage separate
cpu,cuda	pip	26.2.2	exact-version sdist staged; native coverage separate
cpu,cuda	polars	2.0.0	exact-version sdist staged; native coverage separate
cpu,cuda	polars-runtime-32	2.0.0	exact-version sdist staged; native coverage separate
cpu,cuda	propcache	0.5.4	exact-version sdist staged; native coverage separate
cpu,cuda	psutil	7.1.3	exact-version sdist staged; native coverage separate
cpu,cuda	pycparser	3.12	exact-version sdist staged; native coverage separate
cpu,cuda	pyogrio	0.13.0	exact-version sdist staged; native coverage separate
cpu,cuda	pyparsing	3.3.3	exact-version sdist staged; native coverage separate
cpu,cuda	pyproj	3.7.2	exact-version sdist staged; native coverage separate
cpu,cuda	python-dateutil	3.0.0	exact-version sdist staged; native coverage separate
cpu,cuda	python-dotenv	1.2.2	exact-version sdist staged; native coverage separate
cpu,cuda	pytz	2026.5	exact-version sdist staged; native coverage separate
cpu,cuda	requests	2.33.1	exact-version sdist staged; native coverage separate
cpu,cuda	scipy	1.17.1	exact-version sdist staged; native coverage separate
cpu,cuda	seaborn	0.13.2	exact-version sdist staged; native coverage separate
cpu,cuda	setuptools	79.0.1	exact-version sdist staged; native coverage separate
cpu,cuda	shapely	2.0.3	exact-version sdist staged; native coverage separate
cpu,cuda	six	1.17.0	exact-version sdist staged; native coverage separate
cpu,cuda	sympy	1.14.0	exact-version sdist staged; native coverage separate
cpu	torch	2.10.0+cpu	upstream source/build or redistribution mapping required
cuda	torch	2.10.0+cu128	upstream source/build or redistribution mapping required
cpu	torchvision	0.25.0+cpu	upstream source/build or redistribution mapping required
cuda	torchvision	0.25.0+cu128	upstream source/build or redistribution mapping required
cpu,cuda	tqdm	4.67.1	exact-version sdist staged; native coverage separate
cuda	triton	3.6.0	upstream source/build or redistribution mapping required
cpu,cuda	typing_extensions	4.16.0	exact-version sdist staged; native coverage separate
cpu,cuda	tzdata	2026.5	exact-version sdist staged; native coverage separate
cpu,cuda	ultralytics	8.3.249	exact-version sdist staged; native coverage separate
cpu,cuda	ultralytics-thop	2.2.3	exact-version sdist staged; native coverage separate
cpu,cuda	urllib3	2.8.0	exact-version sdist staged; native coverage separate
cpu,cuda	waitress	3.0.2	exact-version sdist staged; native coverage separate
cpu,cuda	wheel	0.46.3	exact-version sdist staged; native coverage separate
cpu,cuda	yarl	1.25.1	exact-version sdist staged; native coverage separate
```

</details>
