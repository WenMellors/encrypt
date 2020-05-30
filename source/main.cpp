#include "mainwindow.h"
#include "connectwindow.h"
#include <QApplication>
#include <QDialog>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ConnectWindow dlg;
    if (dlg.exec() == QDialog::Accepted){
        MainWindow w;
        w.show();
        return a.exec();
    }
    else {
        return 0;
    }
}
