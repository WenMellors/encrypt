#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "mythread.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    int sock;
    int servSock;
    unsigned char* AESEncryptKey;

private slots:
    void on_pushButton_clicked();
    void connectionEstablishedSlot(int, QString, QString, QString);
    void receiveMessageSlot(QString);
    void negotiationCompleteSlot(int, int, unsigned char*);

private:
    Ui::MainWindow *ui;
    MyThread thread;
};
#endif // MAINWINDOW_H
