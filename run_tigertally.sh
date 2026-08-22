#!/bin/bash
# 运行 TigerTally unidbg 复现（JDK8）
set -e
cd /Users/jackjun/Desktop/unidbg
export JAVA_HOME=/Users/jackjun/Library/Java/JavaVirtualMachines/corretto-1.8.0_402/Contents/Home
export JAVA_TOOL_OPTIONS=""

if [ ! -f /tmp/tt_cp.txt ]; then
  mvn -pl unidbg-android dependency:build-classpath -q -DincludeScope=test -Dmdep.outputFile=/tmp/tt_cp.txt
fi
CP="unidbg-android/target/classes:unidbg-android/target/test-classes:$(cat /tmp/tt_cp.txt)"

exec "$JAVA_HOME/bin/java" -cp "$CP" com.tigertally.TigerTallyTrace
