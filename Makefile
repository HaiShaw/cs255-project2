target: mitm

JAVA            = java
JAVAC           = javac

JAVASRCS        = \
			mitm/MITMProxyServer.java \
			mitm/ConnectionDetails.java \
			mitm/CopyStreamRunnable.java \
			mitm/HTTPSProxyEngine.java \
			mitm/JSSEConstants.java \
			mitm/ProxyEngine.java \
			mitm/ProxyDataFilter.java \
			mitm/MITMPlainSocketFactory.java \
			mitm/MITMSSLSocketFactory.java \
			mitm/MITMSocketFactory.java \
			mitm/StreamThread.java \
			mitm/MITMAdminClient.java \
			mitm/MITMAdminServer.java \

JAVAOBJS        = $(JAVASRCS:.java=.class)

JAVACFLAGS	= -classpath ${CLASSPATH}:.:iaik_jce.jar

.SUFFIXES:	.class .java

.java.class: $*.java
	    $(JAVAC) $(JAVACFLAGS) $*.java;

clean:
	    rm -f mitm/*\$*.class mitm/*.class mitm/*~

mitm:    $(JAVAOBJS)
