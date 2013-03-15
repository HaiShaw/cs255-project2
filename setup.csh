if (${?CLASSPATH} == 0) then
    setenv CLASSPATH
endif
setenv CLASSPATH ${CLASSPATH}:.:iaik_jce.jar
