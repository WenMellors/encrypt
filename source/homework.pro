QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

LIBS += -lssl
LIBS += -lcrypto
# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    aes.cpp \
    aes_ni_support.cpp \
    connectwindow.cpp \
    main.cpp \
    mainwindow.cpp \
    mythread.cpp \
    receiver.cpp \
    rsa.cpp \
    sender.cpp \
    sha256.cpp

HEADERS += \
    aes.h \
    aes_ni_support.h \
    connectwindow.h \
    mainwindow.h \
    mythread.h \
    receiver.h \
    rsa.h \
    sender.h \
    sha256.h \
    tables.h

FORMS += \
    connectwindow.ui \
    mainwindow.ui

TRANSLATIONS += \
    homework_zh_CN.ts

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
