#!/bin/bash

export LC_ALL="C"
set -euo pipefail

cd "$(dirname "$0")"

mvn clean &&
mvn package &&
mkdir target/sms-client &&
cp -a bin target/sms-client &&
cp target/sms-client-*.jar target/sms-client/ &&
cd target/sms-client/bin && ln -sf ../sms-client-*.jar sms-client.jar &&
cd ../../.. &&
tar -czf sms-client.tar.gz -C target sms-client &&
rm -rf target/sms-client
