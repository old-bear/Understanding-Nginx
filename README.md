# Install steps:
1: Append the following parameters to configure:
   ./configure --add-module=mytest/ --add-module=myfilter/ --add-module=testslab/

2: Modify objs/Makefile to use g++ to build addons
   CXX = g++
   LINK = $(CXX)
   objs/addon/mytest/...:
   $(CXX) -c ...
   
3: Append to CFLAGS:
   -Wno-unused-function -Wno-write-strings