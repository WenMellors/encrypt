#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QObject>
#include <QThread>
#include "sender.h"
#include "receiver.h"
#include "rsa.h"
#include "sha256.h"
#include "aes.h"

class MyThread : public QThread
{
    Q_OBJECT
public:
    MyThread();
    void stop();
    QString ipAddr;
    QString port;
    QString port2;
    QString mode;
    int sock;
    int sock2;

protected:
    void run();

private:
    volatile bool stopped;

signals:
    void connectionEstablished(int, QString, QString, QString);
    void receiveMessage(QString);
    void negotiationComplete(int, int, unsigned char*);
};

#endif // MYTHREAD_H
