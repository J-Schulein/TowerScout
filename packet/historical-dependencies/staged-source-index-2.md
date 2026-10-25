<!-- towerscout-cdcai-rehearsal-v1:staged-source-index-2 -->

# Audit appendix: staged dependency source — part 2 of 2

This staged-source index accompanies the same proposed cdcai PR. It covers 379 files totaling 819,748,601 bytes: 95 Debian descriptors, 215 source/patch/signature payloads and 69 Python sdists. Each recorded size/SHA-256 was checked after local download. `snapshot:ID` resolves to `https://snapshot.debian.org/file/ID`; `pypi:PATH` resolves to `https://files.pythonhosted.org/packages/PATH`. Debian objects also match the Snapshot SHA-1. Detached signatures were retained but not verified. No archive setup script was executed. These are preserved rehearsal dependency versions; final images must be reconciled again. Archive availability and matching hashes do not establish full native/static source coverage or final source delivery.

Rows in this part: 128. TSV SHA-256: `f6074e5ee156b95fe044837907eec40f653daf1222f06901c0f8ef94120ee52e`.

<details>
<summary>Machine-readable inventory (tab-separated)</summary>

```tsv
ecosystem	component	version	filename	bytes	sha256	origin
debian	openssl	3.0.22-1~deb12u1	openssl_3.0.22.orig.tar.gz.asc	931	b0cc4a379a7731c3a74c349f6756d85253d83099fd63352cf12407bce4395d19	snapshot:51e4e8ce6452a32a2a800cc933befafcec6e7199
debian	openssl	3.0.22-1~deb12u1	openssl_3.0.22-1~deb12u1.debian.tar.xz	56848	08ee68527218d6d9a0fa4741ec8ffef47646cdcad0ed0822b84bf11677c66108	snapshot:f884f096035976115beaea7d3c52d1a9d88cb03d
debian	p11-kit	0.24.1-2	p11-kit_0.24.1-2.dsc	2501	b88a483cb9afd5556ea4ac64d5df4543123a53bf0e50d1c01454887220259a89	snapshot:17b3318ae431350eb1430526086a6f2ef5ab1abd
debian	p11-kit	0.24.1-2	p11-kit_0.24.1.orig.tar.xz	838304	d8be783efd5cd4ae534cee4132338e3f40f182c3205d23b200094ec85faaaef8	snapshot:4d5c35c8c2d6ee12ed69ab58221d6d515c570089
debian	p11-kit	0.24.1-2	p11-kit_0.24.1.orig.tar.xz.asc	833	48041a234bac05f70519b0d4727e78a129ea80a51baf92c7d419f80b7cbdf0ab	snapshot:62240aea977e7da2661a37ebace8f96c0627ff4c
debian	p11-kit	0.24.1-2	p11-kit_0.24.1-2.debian.tar.xz	23332	9a14085b12cfd90e76008c2809e6557224243e1daeae4fbd7fad97e4396f730f	snapshot:55376b034f5b5c97699b8bb867446b5a92ea1136
debian	pam	1.5.2-6+deb12u2	pam_1.5.2-6+deb12u2.dsc	2038	049316ffb7c8be35b14e6815351397b52d65f283041f90fecf884db2c0bec7b1	snapshot:f9f1b289b658fda25d8738e47bf885b1718066f6
debian	pam	1.5.2-6+deb12u2	pam_1.5.2.orig.tar.xz	988784	e4ec7131a91da44512574268f493c6d8ca105c87091691b8e9b56ca685d4f94d	snapshot:8d20308cbf17823e9b88b01c2c70df3e1ad9d654
debian	pam	1.5.2-6+deb12u2	pam_1.5.2-6+deb12u2.debian.tar.xz	137648	17f5ead07046651fd2847b13f657e559af8ef6b43d2092cf1c5a7eea305ae01c	snapshot:2a0f1b09424b7046693514e475c85eb427c450a5
debian	pcre2	10.42-1+deb12u2	pcre2_10.42-1+deb12u2.dsc	2371	63be58a94a6d2c7f03324cc0fe1ffb32d1f366d82d0fabef581ba3cc8a8ba5a6	snapshot:2c1195561d617b701296c40ef94746c3ad62f3ff
debian	pcre2	10.42-1+deb12u2	pcre2_10.42.orig.tar.gz	2397194	c33b418e3b936ee3153de2c61cc638e7e4fe3156022a5c77d0711bcbb9d64f1f	snapshot:0c265c2e3b8325db8d87d06e8a4cc31ce4cbc731
debian	pcre2	10.42-1+deb12u2	pcre2_10.42-1+deb12u2.diff.gz	16865	b28d4aeaa3198fcf2f41dffddec3d673c8ef53286ced930599f009522da11372	snapshot:1b946810fd1d448a4c951880d346e8b8cbcbe296
debian	perl	5.36.0-7+deb12u4	perl_5.36.0-7+deb12u4.dsc	2922	6f71e571ae69894ad2115013bbc3207e77dc796581e30a62be0297e7d90ee7b9	snapshot:deee455a754c1dff25218c26f68898317f4842e3
debian	perl	5.36.0-7+deb12u4	perl_5.36.0.orig-regen-configure.tar.xz	417784	10ac353bc5a933403afe60ed1817e7a456f99bdbcaf80c1cdb0eb3a08ea56d4e	snapshot:482ccf337df6318fad5c2621afbe6794d58a0ec5
debian	perl	5.36.0-7+deb12u4	perl_5.36.0.orig.tar.xz	13051500	0f386dccbee8e26286404b2cca144e1005be65477979beb9b1ba272d4819bcf0	snapshot:938c56a77ae094eb7f5019318a5e4efb2d9c74fa
debian	perl	5.36.0-7+deb12u4	perl_5.36.0-7+deb12u4.debian.tar.xz	190620	f49d224fa9a6a356e1140f95fb5c864864b5423c9aece94cc68b4d348a3694b6	snapshot:6fac7e37c9a661d5b3c2ca8f9bfbe64bd7d70398
debian	readline	8.2-1.3	readline_8.2-1.3.dsc	2553	05497ea99bef3f14b8d502cbe3f84fe7bbc0bce1c4f139ca32f0fd60dcac977e	snapshot:e1c7e6d091e872bbf80e7ddb64bb99a3d037359e
debian	readline	8.2-1.3	readline_8.2.orig.tar.gz	3043952	3feb7171f16a84ee82ca18a36d7b9be109a52c04f492a053331d7d1095007c35	snapshot:97ad98be243a857b639c0f3da2fe7d81c6d1d36e
debian	readline	8.2-1.3	readline_8.2-1.3.debian.tar.xz	30016	8cd3c02d6c07b4cf57da607de168a9e347ee05c31857f0f6236fe3df4fc207d9	snapshot:8fef2c52ad945f1561798fc60249db324066f503
debian	sed	4.9-1+deb12u1	sed_4.9-1+deb12u1.dsc	2038	6bf366b84fd2025e355689e524132b3c38a2b4ef136de2e6129595be1e3bdd4f	snapshot:83f4188dcb275a26d52d80b651b752a90c3f9de9
debian	sed	4.9-1+deb12u1	sed_4.9.orig.tar.xz	1397092	6e226b732e1cd739464ad6862bd1a1aba42d7982922da7a53519631d24975181	snapshot:8ded1b543f1f558cbd5d7b713602f6a8ee84bde4
debian	sed	4.9-1+deb12u1	sed_4.9-1+deb12u1.debian.tar.xz	63548	4346634a4c0b3977bf6a6b6d27f187fb203f547dda8267bb8a42d1323487f6f0	snapshot:ca046c69b296ae8949945aacdef3d43ee11073ac
debian	shadow	1:4.13+dfsg1-1+deb12u2	shadow_4.13+dfsg1-1+deb12u2.dsc	2433	624b24453887abb8d1e60cb6a159180685682ff149393095ba0a55fb2960e4f0	snapshot:d247b6ed3624ee276d1558235e51cacae0a3968c
debian	shadow	1:4.13+dfsg1-1+deb12u2	shadow_4.13+dfsg1.orig.tar.xz	1811752	a8bb3a2aceff1cbe39d0f50687dcc1d7e7be0516a9d954d8e2eedb93f5906207	snapshot:521490d181c42fd2d9c19e7358a8b035e1e0db18
debian	shadow	1:4.13+dfsg1-1+deb12u2	shadow_4.13+dfsg1-1+deb12u2.debian.tar.xz	82876	76272ade06e374596e8d90af58e859dc83293a2fb85cb77ab407687b4f4fdb66	snapshot:ad575aaeeed903e37857242b21e8270f22e3f2b5
debian	sqlite3	3.40.1-2+deb12u2	sqlite3_3.40.1-2+deb12u2.dsc	2519	ee3459ae9d00939741c7708fc1b8ce1bde12d8c3fb1dfa005bbbc8651d884e23	snapshot:0515bc4edf03de34d564ce21d52e0f208cc64654
debian	sqlite3	3.40.1-2+deb12u2	sqlite3_3.40.1.orig-www.tar.xz	5865720	a5e95a18d1b59729278860559ded78751b9163ffb5bb906c5cd24c015f71d5fd	snapshot:6bbac3be3545e2440a9ea2d9b70797e61dc3b398
debian	sqlite3	3.40.1-2+deb12u2	sqlite3_3.40.1.orig.tar.xz	8019048	aaa776260ab4dc976db34aa7891819484c8676b5b2783123ebc6301e2ca5d655	snapshot:92fa12f357ce9bc383c9612518c46f9b546ed43a
debian	sqlite3	3.40.1-2+deb12u2	sqlite3_3.40.1-2+deb12u2.debian.tar.xz	34260	0843bc12e4364076477935ce313a6d0796fd899a989ff18ebb6545540e10e4ca	snapshot:4fc38879135dfcdd17f581e2bd654aa4a13e4385
debian	systemd	252.39-1~deb12u2	systemd_252.39-1~deb12u2.dsc	6574	f2f952ae61fd40f1ef3ee48c8721e23eaaec5396ef5f1b0c2e138d78fade9c6e	snapshot:b947e684578a6e8a8f2775f06e80acda625c7a95
debian	systemd	252.39-1~deb12u2	systemd_252.39.orig.tar.gz	12399886	08a54a6c4d4cf969fc025eaa8922a55d6bc458100c242510b56c96e7d72af1c5	snapshot:0abad77a3d520d8f037125cf69834adefc14d4ad
debian	systemd	252.39-1~deb12u2	systemd_252.39-1~deb12u2.debian.tar.xz	177476	27c548c678593cbe82e1701fc480bfe56e99b8f8750cbc09e720b6aa4fcbffaf	snapshot:138f1b3e25afe727f3c018e4d3d71e4eb60e834e
debian	sysvinit	3.06-4	sysvinit_3.06-4.dsc	2359	f153cd1ef48698089494aac14cebdcb8130ce4d4af5533a41cd3f1950e9e42fa	snapshot:00631229c6f1e13d72cab7d5e4943f8e9cb05a5a
debian	sysvinit	3.06-4	sysvinit_3.06.orig.tar.gz	466092	233d784ca152ce2b4b42a0723948f0cd2d36d4eae5acb9dab1457c1dd85b1a66	snapshot:a6268eb72c2ac7f801884a69e67ef3f072f7cd76
debian	sysvinit	3.06-4	sysvinit_3.06-4.debian.tar.xz	134904	a64de1c40fe55a5b5f1ed0aaf471a7b35a294292530637fab016cbcebd600a43	snapshot:d9431d3921bac49b0d340c6d0bad4a12ec094fb1
debian	tar	1.34+dfsg-1.2+deb12u1	tar_1.34+dfsg-1.2+deb12u1.dsc	2185	c092b25be17ab3b138aabb756497b038516a3f7d23604ccd4bf76ebbabff7a27	snapshot:b041848f934f959206db89805cfd81d0965a3e18
debian	tar	1.34+dfsg-1.2+deb12u1	tar_1.34+dfsg.orig.tar.xz	1981736	7d57029540cb928394defb3b377b3531237c947e795b51aa8acac0c5ba0e4844	snapshot:4f37d162cb262830092ae25aab61abb08785181c
debian	tar	1.34+dfsg-1.2+deb12u1	tar_1.34+dfsg-1.2+deb12u1.debian.tar.xz	21464	e7cdc112e6810a0827b6081f6a4115eb630679a5f3d7cceffbc236d6b8d46d69	snapshot:14af8130f92f0812982131201d88032157b52b3b
debian	tzdata	2026c-0+deb12u1	tzdata_2026c-0+deb12u1.dsc	2396	0ca4eade11f843446aad110966ba335cd218f0897a1a51b82bd2b4104d6a7547	snapshot:c3c77fe2797608abc44f87e1d461b5e0878e809b
debian	tzdata	2026c-0+deb12u1	tzdata_2026c.orig.tar.gz	475694	e4a178a4477f3d0ea77cc31828ff72aa38feff8d61aa13e7e99e142e9d902be4	snapshot:25e5390e8b06c4dd9a7dea4d4a079631c1dd312e
debian	tzdata	2026c-0+deb12u1	tzdata_2026c.orig.tar.gz.asc	833	26cd02e034eed682aa911d224bca3247ff15914df317e3bb0b1a01dc557b46fe	snapshot:ff388761981f8a9754f06876c3ba96b560149882
debian	tzdata	2026c-0+deb12u1	tzdata_2026c-0+deb12u1.debian.tar.xz	122188	bc6f8b573203f7e3802d6106eb814d2162c8ad7a2d3e6dcbc73d4cf87fe0986d	snapshot:72e09887582494e0988ec27f58fbe3137f265df8
debian	usrmerge	37~deb12u1	usrmerge_37~deb12u1.dsc	1643	3a561ff99013607db5bc61721aae08a236afc4b04b13baab17fb2e8d18fc0b7f	snapshot:7aa4a7c6f9b6f5d7c22a7603ae6fc72a7b9eb7e9
debian	usrmerge	37~deb12u1	usrmerge_37~deb12u1.tar.xz	15136	351ed3d74135ac82d686b3b93700976f269229e7fae37491fa79758a45c96ff4	snapshot:0f2cf6710e7e80ecde66c352a7c830ee817615ce
debian	util-linux	2.38.1-5+deb12u3	util-linux_2.38.1-5+deb12u3.dsc	4579	0fe5fcd2b83d0465e32ca5cb9d8319e9b6fbf14c9a69abfd7ea905e45fa90b67	snapshot:4fd1af2788d436250f46d6463f640dbfe5a6fda2
debian	util-linux	2.38.1-5+deb12u3	util-linux_2.38.1.orig.tar.xz	7495904	60492a19b44e6cf9a3ddff68325b333b8b52b6c59ce3ebd6a0ecaa4c5117e84f	snapshot:f62a7b6fe64ce7f4569b57d7d2d0875b39f79836
debian	util-linux	2.38.1-5+deb12u3	util-linux_2.38.1-5+deb12u3.debian.tar.xz	121964	d46b85313f536fc4831a69ba3fa2c8160450b5b26c7c5dfafce4f078fe4f205c	snapshot:d1c733ba8e30dd9bad9b1ff40f308df03c765d47
debian	xxhash	0.8.1-1	xxhash_0.8.1-1.dsc	1966	4a961627c06efc8fa3bc4b06ee9dba6cfaf092f2550b88d63e9218a2728721b4	snapshot:06a26c163a64200b32630a4474a7ea8a00fe9fbc
debian	xxhash	0.8.1-1	xxhash_0.8.1.orig.tar.gz	171552	3bb6b7d6f30c591dd65aaaff1c8b7a5b94d81687998ca9400082c739a690436c	snapshot:a92c9a9cfbef23e52f2d1b581cb9926c680d261d
debian	xxhash	0.8.1-1	xxhash_0.8.1-1.debian.tar.xz	4572	d40aa223e90b85435082857b64573541ba9a995841717496e8975aed97241550	snapshot:c07fee2c29ee74cdce53a0a3228c646af7a9281e
debian	xz-utils	5.4.1-1+deb12u2	xz-utils_5.4.1-1+deb12u2.dsc	2442	bffc9917562b5787661379621bb1f7510bf7271b03d8ce4181cebc84b90d3c35	snapshot:63eed26d58753196bc7a70d19121bdaf901c9ad4
debian	xz-utils	5.4.1-1+deb12u2	xz-utils_5.4.1.orig.tar.xz	1485272	5d9827aa1875b21c288f78864bb26d2650b436ea8d2cad364e4921eb6266a5a5	snapshot:8facb914772e5963d86f9cdd781c928009879b3b
debian	xz-utils	5.4.1-1+deb12u2	xz-utils_5.4.1-1+deb12u2.debian.tar.xz	95356	7e0b1d1448520ea4f88ec05136a88f07564cc4a1abd6dfcf53c1f822a3e4f64f	snapshot:233eb3cf93758f5aa82547ef30057c1451a40991
debian	z3	4.8.12-3.1	z3_4.8.12-3.1.dsc	2663	0e5db5248212a72d3dc3fe99873181161649ff03d89de726bbe6f57604488008	snapshot:d5bd0d44e8a45bd8f7b48039d2fbe6d5c5802380
debian	z3	4.8.12-3.1	z3_4.8.12.orig.tar.gz	4803435	e3aaefde68b839299cbc988178529535e66048398f7d083b40c69fe0da55f8b7	snapshot:f4443c6beedb46e8a0785529b477b2f811901cc3
debian	z3	4.8.12-3.1	z3_4.8.12-3.1.debian.tar.xz	10420	5bb616648de1d82f5563377e1640e59dd653b6beac3b6513358362e5dbd925fb	snapshot:bac6eb0fea1ed8ca07661efc29cdbfb08c3a02b8
debian	zlib	1:1.2.13.dfsg-1	zlib_1.2.13.dfsg-1.dsc	2399	3fa1e6b2fc525062aa88207dda52fed8e045373c809d362fe8a2bfbf7cf515a8	snapshot:38bfe208218e987bd3710e5f6201f5ee6cc35f34
debian	zlib	1:1.2.13.dfsg-1	zlib_1.2.13.dfsg.orig.tar.bz2	1239825	71feb7947e3c00ef125f83b79a4e529bde31171e5babe48b391f06758d1ab0a1	snapshot:4fec854a7c5fe543e44c12afa365642c0e6b5ded
debian	zlib	1:1.2.13.dfsg-1	zlib_1.2.13.dfsg-1.debian.tar.xz	15700	f66cf3d4f2d7defcd4d1fd1fb0a11ee39f1e01b42ec7d059c9dc5c1695133c44	snapshot:41df4cb006cd857de65ec72f9538ffdf6d1d2f2c
python	Flask	3.1.3	flask-3.1.3.tar.gz	759004	0ef0e52b8a9cd932855379197dd8f94047b359ca0a78695144304cb45f87c9eb	pypi:26/00/35d85dcce6c57fdc871f3867d465d780f302a175ea360f62533f12b27e2b/flask-3.1.3.tar.gz
python	Flask-Session	0.6.0	flask_session-0.6.0.tar.gz	13090	b1ed06cf4c5a211305579a132e81307d242cec6fe2714a276405730ffd22a034	pypi:ed/33/62658075ebfbed233ecc2e95df956327bfbce08444d2761690c470a08184/flask_session-0.6.0.tar.gz
python	Jinja2	3.1.6	jinja2-3.1.6.tar.gz	245115	0137fb05990d35f1275a587e9aee6d56da821fc83491a0fb838183be43f66d6d	pypi:df/bf/f7da0350254c0ed7c72f3e33cef02e048281fec7ecec5f032d4aac52226b/jinja2-3.1.6.tar.gz
python	MarkupSafe	3.0.3	markupsafe-3.0.3.tar.gz	80313	722695808f4b6457b320fdc131280796bdceb04ab50fe1795cd540799ebe1698	pypi:7e/99/7690b6d4034fffd95959cbe0c02de8deb3098cc577c67bb6a24fe5d7caa7/markupsafe-3.0.3.tar.gz
python	PyYAML	6.0.3	pyyaml-6.0.3.tar.gz	130960	d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f	pypi:05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz
python	Werkzeug	3.1.9	werkzeug-3.1.9.tar.gz	940188	55ca7c70a75689be937aa27f8ff4b018f06ff4838fc73045560bf0f5a1291060	pypi:a4/34/4dd12fc8bb7d61c91467ec3efe415ffa7d5456f799954b40c5bbaeae470e/werkzeug-3.1.9.tar.gz
python	aiofiles	23.2.1	aiofiles-23.2.1.tar.gz	32072	84ec2218d8419404abcb9f0c02df3f34c6e0a68ed41072acfb1cef5cbc29051a	pypi:af/41/cfed10bc64d774f497a86e5ede9248e1d062db675504b41c320954d99641/aiofiles-23.2.1.tar.gz
python	aiohappyeyeballs	2.7.1	aiohappyeyeballs-2.7.1.tar.gz	24757	065665c041c42a5938ed220bdcd7230f22527fbec085e1853d2402c8a3615d9d	pypi:ce/f4/eec0465c2f67b2664688d0240b3212d5196fd89e741df67ddb81f8d35658/aiohappyeyeballs-2.7.1.tar.gz
python	aiohttp	3.14.4	aiohttp-3.14.4.tar.gz	8077839	831fc5bd39ec2517851e348f613ddb5447a47cf4b71cb09845af7ad7ed45d8f9	pypi:93/2f/6a91adaa2dc26877d6ed2f54c0370c8910f019db7d77c5c6a194611e93ea/aiohttp-3.14.4.tar.gz
python	aiosignal	1.4.0	aiosignal-1.4.0.tar.gz	25007	f47eecd9468083c2029cc99945502cb7708b082c232f9aca65da147157b251c7	pypi:61/62/06741b579156360248d1ec624842ad0edf697050bbaf7c3e46394e106ad1/aiosignal-1.4.0.tar.gz
python	attrs	26.1.0	attrs-26.1.0.tar.gz	952055	d03ceb89cb322a8fd706d4fb91940737b6642aa36998fe130a9bc96c985eff32	pypi:9a/8e/82a0fe20a541c03148528be8cac2408564a6c9a0cc7e9171802bc1d26985/attrs-26.1.0.tar.gz
python	blinker	1.9.0	blinker-1.9.0.tar.gz	22460	b4ce2265a7abece45e7cc896e98dbebe6cead56bcf805a3d23136d145f5445bf	pypi:21/28/9b3f50ce0e048515135495f198351908d99540d69bfdc8c1d15b73dc55ce/blinker-1.9.0.tar.gz
python	cachelib	0.17.0	cachelib-0.17.0.tar.gz	135529	f3c7dc8d3c1132ab699681ffdf8a52d341d9425ac1401c538cf0b1d87b1677c8	pypi:c6/f4/b20875916b83f68775093554ce2544b12255396ba69abd93d8903cce0feb/cachelib-0.17.0.tar.gz
python	certifi	2026.10.19	certifi-2026.10.19.tar.gz	137598	035c1e85572b141bf1c3a3eff0e33a8eb74917522f2559075ff8d2fea780a1ae	pypi:a6/bd/1436c50cc46699de0230fbaacc1d1de7bfec413176099949e9d5112e88f2/certifi-2026.10.19.tar.gz
python	cffi	2.1.1	cffi-2.1.1.tar.gz	530807	dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be	pypi:9e/ef/008a1939e372c06329a3fce4279c02f328488f3526744906eeec3da7ad5f/cffi-2.1.1.tar.gz
python	charset-normalizer	3.5.2	charset_normalizer-3.5.2.tar.gz	172659	39de2a259fc954455c57274dc94c79d5842774e1247a016aff30bc0efed0f4ef	pypi:33/1c/f41d4e74c28ab327ff3acd36053f7ea506c55872d7a90b0fa71aa3ab0c89/charset_normalizer-3.5.2.tar.gz
python	click	8.5.0	click-8.5.0.tar.gz	382235	ba0d2089de75ea0310e2dde03160e6ca10009947fb95a182f9b54021bb272e34	pypi:c7/0e/7fa0ef50764b67090eca4114772a2abf8b6148198475e54c660b97caeee6/click-8.5.0.tar.gz
python	click-plugins	1.1.1.2	click_plugins-1.1.1.2.tar.gz	8343	d7af3984a99d243c131aa1a828331e7630f4a88a9741fd05c927b204bcf92261	pypi:c3/a4/34847b59150da33690a36da3681d6bbc2ec14ee9a846bc30a6746e5984e4/click_plugins-1.1.1.2.tar.gz
python	cligj	0.7.2	cligj-0.7.2.tar.gz	9803	a4bc13d623356b373c2c27c53dbd9c68cae5d526270bfa71f6c6fa69669c6b27	pypi:ea/0d/837dbd5d8430fd0f01ed72c4cfb2f548180f4c68c635df84ce87956cff32/cligj-0.7.2.tar.gz
python	contourpy	1.3.3	contourpy-1.3.3.tar.gz	13466174	083e12155b210502d0bca491432bb04d56dc3432f95a979b429f2848c3dbe880	pypi:58/01/1253e6698a07380cd31a736d248a3f2a50a7c88779a1813da27503cadc2a/contourpy-1.3.3.tar.gz
python	cryptography	50.0.0	cryptography-50.0.0.tar.gz	880201	eeac2acb5a20ed25e0ad6d1df9891a520b78b404266b6d11778f25d5d691a6c9	pypi:de/41/6cbdcf9142d00fe82836fbb51e503e58088575cf7a0fe1dbff6695bf0840/cryptography-50.0.0.tar.gz
python	cycler	0.12.1	cycler-0.12.1.tar.gz	7615	88bb128f02ba341da8ef447245a9e138fae777f6a23943da4540077d3601eb1c	pypi:a9/95/a3dbbb5028f35eafb79008e7522a75244477d2838f38cbb722248dabc2a8/cycler-0.12.1.tar.gz
python	efficientnet_pytorch	0.7.1	efficientnet_pytorch-0.7.1.tar.gz	21012	00b9b261effce59d2d47aae2ad238c29a2a65175470f41ada7ecac439b7c1ee1	pypi:2e/a0/dd40b50aebf0028054b6b35062948da01123d7be38d08b6b1e5435df6363/efficientnet_pytorch-0.7.1.tar.gz
python	filelock	3.32.3	filelock-3.32.3.tar.gz	218135	0ffa185a3540854c95caa7fa76b76cb219d907415e2c5dc9af25fd970563487f	pypi:7d/64/a02e6765de08964ed371eca577870593245afc9dfac16d037de7c10d18e6/filelock-3.32.3.tar.gz
python	fiona	1.10.1	fiona-1.10.1.tar.gz	444606	b00ae357669460c6491caba29c2022ff0acfcbde86a95361ea8ff5cd14a86b68	pypi:51/e0/71b63839cc609e1d62cea2fc9774aa605ece7ea78af823ff7a8f1c560e72/fiona-1.10.1.tar.gz
python	fonttools	4.67.0	fonttools-4.67.0.tar.gz	3750028	3cb57e6600ca77c0b1729cf8adc23bc0652633a37f18cfa934d9c7bc3de25519	pypi:94/36/102e180f8f5dbaee88b26595b01ca8aa80bf4e62128d9aa94265b3996c96/fonttools-4.67.0.tar.gz
python	frozenlist	1.8.0	frozenlist-1.8.0.tar.gz	45875	3ede829ed8d842f6cd48fc7081d7a41001a56f1f38603f9d49bf3020d59a31ad	pypi:2d/f5/c831fac6cc817d26fd54c7eaccd04ef7e0288806943f7cc5bbf69f3ac1f0/frozenlist-1.8.0.tar.gz
python	fsspec	2026.7.0	fsspec-2026.7.0.tar.gz	317040	c803c40f4cf860b49dea58ee3e1c33cb9c790520e233537e1340049f89b82a88	pypi:00/78/f34251dadb8f3921264a1d9b8946f5e542014ee2614b285261b4e40e6775/fsspec-2026.7.0.tar.gz
python	geopandas	1.1.2	geopandas-1.1.2.tar.gz	336037	33f7b33565c46a45b8459a2ab699ec943fdbb5716e58e251b3c413cf7783106c	pypi:8d/24/5eb5685d7bf89d64218919379f882d19a60f8219d66d833c83b1cf264c95/geopandas-1.1.2.tar.gz
python	idna	3.20	idna-3.20.tar.gz	216463	a7db850025b95ded1eae8a46181a1a6c56c92c96f0e2b005d9ff8dc0210cab44	pypi:f5/08/8eea9d4b8302028f3abb2c0813953f7aec26d33b7a8960ed760e65ff29fa/idna-3.20.tar.gz
python	itsdangerous	2.2.0	itsdangerous-2.2.0.tar.gz	54410	e0050c0b7da1eea53ffaf149c0cfbb5c6e2e2b69c4bef22c81fa6eb73e5f6173	pypi:9c/cb/8ac0172223afbccb63986cc25049b154ecfb5e85932587206f42317be31d/itsdangerous-2.2.0.tar.gz
python	kiwisolver	1.5.1	kiwisolver-1.5.1.tar.gz	104395	f1303ef2eec81262a4b708c3e858afe58d7c75ad91c1c05266eda7673369859a	pypi:ba/07/bd78e6a8fae171ea041ef5bba3ed21a003522fa088834b069b1909981f30/kiwisolver-1.5.1.tar.gz
python	matplotlib	3.11.2	matplotlib-3.11.2.tar.gz	32660610	cec596316640f2b394b8f0daa0ea61a8eae82d017b620b9f202befb972a59ea4	pypi:e7/c8/9aa712a0afb882649424dd8de8ad9aa6235e796e84c6052e8f6dc1598d0d/matplotlib-3.11.2.tar.gz
python	mpmath	1.3.0	mpmath-1.3.0.tar.gz	508106	7a28eb2a9774d00c7bc92411c19a89209d5da7c4c9a9e227be8330a23a25b91f	pypi:e0/47/dd32fa426cc72114383ac549964eecb20ecfd886d1e5ccf5340b55b02f57/mpmath-1.3.0.tar.gz
python	multidict	6.9.1	multidict-6.9.1.tar.gz	182404	0f06e60fa190aa7abd0914c2a766736fdc8e9f34878c4346338534b73d1b20e2	pypi:d6/99/1d4d69c3512d0ddbfa3a1b69cfd9a151012ab2eb4eabbb096201b1f0b7d8/multidict-6.9.1.tar.gz
python	networkx	3.6.1	networkx-3.6.1.tar.gz	2517025	26b7c357accc0c8cde558ad486283728b65b6a95d85ee1cd66bafab4c8168509	pypi:6a/51/63fe664f3908c97be9d2e4f1158eb633317598cfa6e1fc14af5383f17512/networkx-3.6.1.tar.gz
python	numpy	1.26.4	numpy-1.26.4.tar.gz	15786129	2a02aba9ed12e4ac4eb3ea9421c420301a0c6460d9830d74a9df87efa4912010	pypi:65/6e/09db70a523a96d25e115e71cc56a6f9031e7b8cd166c1ac8438307c14058/numpy-1.26.4.tar.gz
python	opencv-python	4.9.0.80	opencv-python-4.9.0.80.tar.gz	92896686	1a9f0e6267de3a1a1db0c54213d022c7c8b5b9ca4b580e80bdc58516c922c9e1	pypi:25/72/da7c69a3542071bf1e8f65336721b8b2659194425438d988f79bc14ed9cc/opencv-python-4.9.0.80.tar.gz
python	packaging	25.0	packaging-25.0.tar.gz	165727	d443872c98d677bf60f6a1f2f8c1cb748e8fe762d2bf9d3148b5599295b0fc4f	pypi:a1/d4/1fc4078c65507b51b96ca8f8c3ba19e6a61c8253c72794544580a7b6c24d/packaging-25.0.tar.gz
python	pandas	2.3.3	pandas-2.3.3.tar.gz	4495223	e05e1af93b977f7eafa636d043f9f94c7ee3ac81af99c13508215942e64c993b	pypi:33/01/d40b85317f86cf08d853a4f495195c73815fdf205eef3993821720274518/pandas-2.3.3.tar.gz
python	pillow	13.0.0	pillow-13.0.0.tar.gz	47058631	cdcd1ba258178f7356d74170c9a81ba4eab6a5d55748bc402a5a2a6fe6be3510	pypi:ce/a4/9cc30690a394a8305e8be4c9036aa16d0dfddadd09079860b582f562496d/pillow-13.0.0.tar.gz
python	pip	26.2.2	pip-26.2.2.tar.gz	1863336	3a8e5c800492787f33a4114ef54444546c340df428974ebba17e0fd47e11af2f	pypi:fa/e8/0842d757e483e895e670f655084cfe8b8c72580c6769a76b30b2789a0608/pip-26.2.2.tar.gz
python	polars	2.0.0	polars-2.0.0.tar.gz	778215	62da109e27a19a9d36657ee25dc035c9d3f87e7bd610526fe467dc37ea7dc115	pypi:8e/e9/001f371ec6a1bb54893f599ceebd56e6144fed4091f09f09fec0021a9276/polars-2.0.0.tar.gz
python	polars-runtime-32	2.0.0	polars_runtime_32-2.0.0.tar.gz	3591339	b5f9afcc742b4a67eabd2c680ff0f12eb02ede9b4bf807bffabd6dbb9a58d5c7	pypi:34/ad/dbb6f6d7070867951532bcfe5e6a648d8777b416b18cddabc07030404e8c/polars_runtime_32-2.0.0.tar.gz
python	propcache	0.5.4	propcache-0.5.4.tar.gz	61545	ff6b113f50bc066a698db5d944d2c6dc7507168dd3341e255a8892fd0715a558	pypi:b3/9a/9fbf4e4ec0c2d7f1c32519fff782ef467859b8faa9fbc5331a96f6395d43/propcache-0.5.4.tar.gz
python	psutil	7.1.3	psutil-7.1.3.tar.gz	489059	6c86281738d77335af7aec228328e944b30930899ea760ecf33a4dba66be5e74	pypi:e1/88/bdd0a41e5857d5d703287598cbf08dad90aed56774ea52ae071bae9071b6/psutil-7.1.3.tar.gz
python	pycparser	3.12	pycparser-3.12.tar.gz	158785	f03387877eab82ce01bbdfd0ba7252ee55a90b1c708d5129e2ce915475cf1db6	pypi:cb/27/eeb9f307bf07060f3d9f9aa0fb8c15b01bdfded0a941e4b2719c7f94cacd/pycparser-3.12.tar.gz
python	pyogrio	0.13.0	pyogrio-0.13.0.tar.gz	313103	9614f27a1891113f80653e0b76b4233ea1fb3beeb1ac46d118ab22e1670f8f13	pypi:de/3c/d2268615e8b749ba59f278b14a495883562e961fa3ad55a9def222bfbd4a/pyogrio-0.13.0.tar.gz
python	pyparsing	3.3.3	pyparsing-3.3.3.tar.gz	1050487	928ae7e20211f3b6f3915a72f06a0cfd29ab9d24279dd6346b6b1a7146397d36	pypi:e4/11/b213bebff182584360cb8d17c72c1677fec5c5c228de439e63bcf8ab1c8f/pyparsing-3.3.3.tar.gz
python	pyproj	3.7.2	pyproj-3.7.2.tar.gz	226279	39a0cf1ecc7e282d1d30f36594ebd55c9fae1fda8a2622cee5d100430628f88c	pypi:04/90/67bd7260b4ea9b8b20b4f58afef6c223ecb3abf368eb4ec5bc2cdef81b49/pyproj-3.7.2.tar.gz
python	python-dateutil	3.0.0	python_dateutil-3.0.0.tar.gz	271066	7ebcb3c29a92f3ceafe79a7a48a5c45677e9e004bbeec5742ac0bbb00560b7a2	pypi:0e/df/f15f80383f152452d8985b36d95cb8751f901a3e0ff4cd27f7e118f168e2/python_dateutil-3.0.0.tar.gz
python	python-dotenv	1.2.2	python_dotenv-1.2.2.tar.gz	50135	2c371a91fbd7ba082c2c1dc1f8bf89ca22564a087c2c287cd9b662adde799cf3	pypi:82/ed/0301aeeac3e5353ef3d94b6ec08bbcabd04a72018415dcb29e588514bba8/python_dotenv-1.2.2.tar.gz
python	pytz	2026.5	pytz-2026.5.tar.gz	318572	fa23724b9c486543b9ff54a327ee7569ac83ade54bb9afd0fc18676620401c86	pypi:14/21/d83d6ef28c4c912c4bb4d1dcf591f7b8c6bde87b9c66f9f454677314e16d/pytz-2026.5.tar.gz
python	requests	2.33.1	requests-2.33.1.tar.gz	134120	18817f8c57c6263968bc123d237e3b8b08ac046f5456bd1e307ee8f4250d3517	pypi:5f/a4/98b9c7c6428a668bf7e42ebb7c79d576a1c3c1e3ae2d47e674b468388871/requests-2.33.1.tar.gz
python	scipy	1.17.1	scipy-1.17.1.tar.gz	30573822	95d8e012d8cb8816c226aef832200b1d45109ed4464303e997c5b13122b297c0	pypi:7a/97/5a3609c4f8d58b039179648e62dd220f89864f56f7357f5d4f45c29eb2cc/scipy-1.17.1.tar.gz
python	seaborn	0.13.2	seaborn-0.13.2.tar.gz	1457696	93e60a40988f4d65e9f4885df477e2fdaff6b73a9ded434c1ab356dd57eefff7	pypi:86/59/a451d7420a77ab0b98f7affa3a1d78a313d2f7281a57afb1a34bae8ab412/seaborn-0.13.2.tar.gz
python	setuptools	79.0.1	setuptools-79.0.1.tar.gz	1367909	128ce7b8f33c3079fd1b067ecbb4051a66e8526e7b65f6cec075dfc650ddfa88	pypi:bb/71/b6365e6325b3290e14957b2c3a804a529968c77a049b2ed40c095f749707/setuptools-79.0.1.tar.gz
python	shapely	2.0.3	shapely-2.0.3.tar.gz	280488	4d65d0aa7910af71efa72fd6447e02a8e5dd44da81a983de9d736d6e6ccbe674	pypi:36/8f/03929218f8d7003c3eafa5ffad1fb3f185459d336fa9cc31d3e67f442f97/shapely-2.0.3.tar.gz
python	six	1.17.0	six-1.17.0.tar.gz	34031	ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81	pypi:94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz
python	sympy	1.14.0	sympy-1.14.0.tar.gz	7793921	d3d3fe8df1e5a0b42f0e7bdf50541697dbe7d23746e894990c030e2b05e72517	pypi:83/d3/803453b36afefb7c2bb238361cd4ae6125a569b4db67cd9e79846ba2d68c/sympy-1.14.0.tar.gz
python	tqdm	4.67.1	tqdm-4.67.1.tar.gz	169737	f8aef9c52c08c13a65f30ea34f4e5aac3fd1a34959879d7e59e63027286627f2	pypi:a8/4b/29b4ef32e036bb34e4ab51796dd745cdba7ed47ad142a9f4a1eb8e0c744d/tqdm-4.67.1.tar.gz
python	typing_extensions	4.16.0	typing_extensions-4.16.0.tar.gz	113555	dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5	pypi:f6/cc/6253133b5bb138fc3306cebfbda2c520f545d36b5be2c7255cc528bb45d6/typing_extensions-4.16.0.tar.gz
python	tzdata	2026.5	tzdata-2026.5.tar.gz	200404	8cc73c0a0bfca7dbfa59235d60b2eff82231dee33f53d206db1acd9173cfc0a7	pypi:d9/68/f1b440335057bfce71b6e50a9d09445aa2ecbd08359a337976627b8409e7/tzdata-2026.5.tar.gz
python	ultralytics	8.3.249	ultralytics-8.3.249.tar.gz	989824	9686be83d5ada2fbe9cedeaba1e59a24d87a2a97c653bb5b13741ac274308630	pypi:c1/94/082b7a6466d475a9ddbc163a5d25858bd6a6c1d6743c8d6c51d68525bb24/ultralytics-8.3.249.tar.gz
python	ultralytics-thop	2.2.3	ultralytics_thop-2.2.3.tar.gz	39816	141cea7d1af7fda04b135b5070d19d84f2272c76c5401de9e47581c23e7c5c60	pypi:f9/6f/f7dd1959a3f0d3d7417800f6c54112a0bdc9f0529470bb0558c326cd19f3/ultralytics_thop-2.2.3.tar.gz
python	urllib3	2.8.0	urllib3-2.8.0.tar.gz	458972	63bf2ead4c879426ebf22ef2a781eeb4aa3b4ae798a0435506f8687fd5bb9b63	pypi:e3/05/b17359e1cefb4f909b5e40b1b90a496d987258916dbbf88e842c729f510e/urllib3-2.8.0.tar.gz
python	waitress	3.0.2	waitress-3.0.2.tar.gz	179901	682aaaf2af0c44ada4abfb70ded36393f0e307f4ab9456a215ce0020baefc31f	pypi:bf/cb/04ddb054f45faa306a230769e868c28b8065ea196891f09004ebace5b184/waitress-3.0.2.tar.gz
python	wheel	0.46.3	wheel-0.46.3.tar.gz	60605	e3e79874b07d776c40bd6033f8ddf76a7dad46a7b8aa1b2787a83083519a1803	pypi:89/24/a2eb353a6edac9a0303977c4cb048134959dd2a51b48a269dfc9dde00c8a/wheel-0.46.3.tar.gz
python	yarl	1.25.1	yarl-1.25.1.tar.gz	246245	03dd38de09bc213e9a8b29761eec33ee1d5318dac0e49d8af36e4d27830e23a7	pypi:75/16/e8be8e2fb175bbf41a0680381a319f1199fae256588241a2ac8677eafb49/yarl-1.25.1.tar.gz
```

</details>
