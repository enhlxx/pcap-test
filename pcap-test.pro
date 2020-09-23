TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp

HEADERS += \
    libnet/libnet-headers.h \
    libnet/libnet-macros.h
