#!/usr/bin/env bash

#DATA_DIR=/var/lib/grnoc/netsage/
DATA_DIR=/data/cache/
mkdir -p $DATA_DIR && echo "Cache directory ${DATA_DIR} created" || echo "cache dir ${DATA_DIR} already exists"

FILES="GeoLite2-ASN scireg GeoLite2-City"
CAIDA_FILES="CAIDA-org-lookup"

function downloadFiles() {
    ext=$1
    shift 1
    ## Download all files to temporary destination
    for f in $@; do
        wget https://scienceregistry.grnoc.iu.edu/exported/${f}.${ext} --no-use-server-timestamps -q -O ${DATA_DIR}/$f.tmp
    done

    ## Rename the temporary files to replace the production ones.
    for f in $@; do
        mv ${DATA_DIR}/$f.tmp ${DATA_DIR}/${f}.${ext}
    done

}

echo "Download ScienceRegistry and maxmind"
downloadFiles mmdb $FILES
echo "Download Caida Files"
downloadFiles csv $CAIDA_FILES
