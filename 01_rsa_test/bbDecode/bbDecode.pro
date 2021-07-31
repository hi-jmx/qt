#-------------------------------------------------
#
# Project created by QtCreator 2021-07-08T16:20:37
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = bbDecode
TEMPLATE = app


SOURCES += main.cpp\
        dialog.cpp

HEADERS  += dialog.h

FORMS    += dialog.ui

LIBS += -L$$PWD/rsa -llibcrypto-1_1
LIBS += -L$$PWD/rsa -llibssl-1_1

INCLUDEPATH += $$PWD/rsa/inc

RC_FILE = myapp.rc
