# Hidden task set: SHA-256 commitment

Published before the hidden set is run. The ten hidden tasks and their expected-outcome sheet are kept outside this repository until the run. When they are added, their SHA-256 digests must match the values below byte for byte.

```
0b69d3486ff8115553293b4ce26b3d393a0794fa3cca490c27782d755ce9d258  H01.yaml
12b954ab841e1c6986b61e3df99520294682e49d0d1d882850082df613c47e11  H02.yaml
51c1f5f729e8b97a7e8f68b87f1d97dd4bc77043152592ccdda6bc60d1976c67  H03.yaml
ad6c2371d501b08994d8e794033b5806b73e13c35ad13d42e3e62d77ed720228  H04.yaml
92d0706d38941564bbab1dde0fca03e9fe6a50947891577d991aa68e4fdd1fcd  H05.yaml
68a072a86b3420a7bd9f8b8d61cad3b445afeaf0b9785bf1beb9f7f82e7f7a9f  H06.yaml
1068087925f13b42199bd736b5a32801e0cd20555bca405a2ad5632cdd36a5bf  H07.yaml
f0c26791bf818d24c8bdddea4bd2ae2cf3f148540e003dc767b993a64b0806aa  H08.yaml
97f3365bb6f06c8724cf13abd9bc92b99ad997dc0a1646d38a37cf120bc5e5e6  H09.yaml
9f72325d4e38b4f80f1964b0c1d533a5e3d82865bbf9e141e70f6a034aa1a4eb  H10.yaml
76a40fbe6fdb04341081e6d98873a0814a52abe5ca9be520e19f460f8fda113c  HIDDEN_SET.md
```

To check after publication, run `shasum -a 256 -c` on the list above from the directory that holds the files.
