#include "connectwindow.h"
#include "ui_connectwindow.h"
#include <QRegExpValidator>
#include <QRegExp>
#include <QFile>
#include <QTextStream>

ConnectWindow::ConnectWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ConnectWindow)
{
    ui->setupUi(this);
    QRegExp regExp("(0|[1-9]\\d{0,2})\\.(0|[1-9]\\d{0,2})\\.(0|[1-9]\\d{0,2})\\.(0|[1-9]\\d{0,2})");
    ui->lineEdit->setValidator(new QRegExpValidator(regExp, this));
    QRegExp regExp2("[1-9]\\d{0,4}");
    ui->lineEdit_2->setValidator(new QRegExpValidator(regExp2, this));
}

ConnectWindow::~ConnectWindow()
{
    delete ui;
}

void ConnectWindow::on_pushButton_clicked()
{
    QFile aFile("place.tmp");
    if (aFile.open(QIODevice::WriteOnly|QIODevice::Text)) {
        QTextStream aStream(&aFile);
        aStream << ui->lineEdit->text() << "\n" << ui->lineEdit_2->text() << "\nreceive";
        accept();
    }
}

void ConnectWindow::on_pushButton_2_clicked()
{
    QFile aFile("place.tmp");
    if (aFile.open(QIODevice::WriteOnly|QIODevice::Text)) {
        QTextStream aStream(&aFile);
        aStream << ui->lineEdit->text() << "\n" << ui->lineEdit_2->text() << "\nsend";
        accept();
    }
}
