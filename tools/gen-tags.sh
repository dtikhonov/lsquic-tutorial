#!/usr/bin/env bash
#
# Generate tags for lsquic project
#
# If your `ctags' is not Universal Ctags, set UCTAGS environment variable to
# point to it.

tmpfile=.tags.$$$RANDOM
addl=.addl.$$$RANDOM

ctags_bin=${UCTAGS:-ctags}

export LC_ALL=C         # So that sort(1) behaves
$ctags_bin -f $tmpfile -R -I SLIST_ENTRY+=void -I LIST_ENTRY+=void \
    -I STAILQ_ENTRY+=void -I TAILQ_ENTRY+=void -I CIRCLEQ_ENTRY+=void \
    -I TAILQ_ENTRY+=void -I SLIST_HEAD+=void -I LIST_HEAD+=void \
    -I STAILQ_HEAD+=void -I TAILQ_HEAD+=void -I CIRCLEQ_HEAD+=void \
    -I TAILQ_HEAD+=void \
    *.[ch] lsquic/include lsquic/src/liblsquic lsquic/src/lshpack \
&& \
: some special sauce for conn_iface: && \
egrep '^(mini|full|ietf_full|id24_full|evanescent)_conn_ci_' $tmpfile | sed -r 's/(mini|full|ietf_full|id24_full|evanescent)_conn_//' > $addl && \
cat $addl >> $tmpfile && \
egrep '^(nocopy|hash|error)_di_' $tmpfile | sed -r 's/(nocopy|hash|error)_//' > $addl && \
egrep '^(gquic)_(be|Q046|Q050)_' $tmpfile | sed -r 's/(gquic)_(be|Q046|Q050)_/pf_/' >> $addl && \
egrep '^ietf_v[0-9][0-9]*_' $tmpfile | sed -r 's/^ietf_v[0-9][0-9]*_/pf_/' >> $addl && \
egrep '^(stock)_shi_' $tmpfile | sed -r 's/(stock)_//' >> $addl && \
egrep '^(iquic)_esf_' $tmpfile | sed -r 's/(iquic)_//' >> $addl && \
egrep '^(gquic[0-9]?)_esf_' $tmpfile | sed -r 's/(gquic[0-9]?)_//' >> $addl && \
egrep '^(iquic)_esfi_' $tmpfile | sed -r 's/(iquic)_//' >> $addl && \
egrep '^(lsquic_cubic|lsquic_bbr)_' $tmpfile | sed -r 's/(lsquic_cubic|lsquic_bbr)_/cci_/' >> $addl && \
cat $tmpfile >> $addl && \
sort $addl > $tmpfile && \
rm $addl && \
$ctags_bin -a -f $tmpfile /usr/include/sys/queue.h \
&& \
mv $tmpfile tags \
|| \
rm $tmpfile
