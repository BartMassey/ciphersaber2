#!/bin/sh
# Copyright © 2015 Bart Massey
TMPP=/tmp/test-plain-$$
TMPC=/tmp/test-cipher-$$

CS2=../dist/build/cs2/cs2

if [ ! -x $CS2 ]
then
    ( cd .. ; cabal configure && cabal build )
    if [ $? -ne 0 ]
    then
        echo "could not build cs2" >&2
        exit 1
    fi
fi

cat <<EOF |
cstest1.cs1 asdfg cstest1.txt 1
cstest2.cs1 SecretMessageforCongress cstest2.txt 1
cknight.cs1 ThomasJefferson cknight.gif 1
cstest.cs2 asdfg cstest.txt 10
EOF
while read CIPHER KEY PLAIN R
do
    $CS2 -r $R -d $KEY <$CIPHER >$TMPP
    if ! cmp $TMPP $PLAIN
    then
        echo "decryption fail: $CIPHER" >&2
        exit 1
    fi
    $CS2 -r $R -e $KEY <$PLAIN >$TMPC
    $CS2 -r $R -d $KEY <$TMPC >$TMPP
    if ! cmp $TMPP $PLAIN
    then
        echo "encryption fail: $CIPHER" >&2
        exit 1
    fi
done
[ $? -eq 0 ] && rm -f $TMPP $TMPC
