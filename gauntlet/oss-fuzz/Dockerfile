# Shared by OSS-Fuzz (projects/citadel-v3/) and ClusterFuzzLite (.clusterfuzzlite/).
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN git clone --depth 1 https://github.com/mrcord77/citadel-v3 $SRC/citadel-v3
WORKDIR $SRC/citadel-v3
COPY build.sh $SRC/
