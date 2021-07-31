QT += core
QT -= gui

TARGET = rsa_test
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    rsa_test.cpp

HEADERS += \
    rsa_test.h

LIBS += -L$$PWD/rsa -llibcrypto-1_1
LIBS += -L$$PWD/rsa -llibssl-1_1

INCLUDEPATH += $$PWD/rsa/inc

