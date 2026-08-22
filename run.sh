cd /Users/jackjun/Desktop/unidbg
mvn -q -pl unidbg-android -am compile test-compile -Dmaven.test.skip=false
java -cp "unidbg-android/target/classes:unidbg-android/target/test-classes:$(mvn -pl unidbg-android dependency:build-classpath -q -DincludeScope=test -Dmdep.outputFile=/dev/stdout)" com.xhs.Xhs921
cd -