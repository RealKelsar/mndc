#include <QtWidgets/QApplication>
#include <QtNetwork/QHostAddress>
#include "mainwindow.h"

bool isIP( QString ip)
{
	QHostAddress address( ip);
	return !address.isNull();
}

bool isHostname( QString host)
{
    QRegExp exp("[^ %&:@§$/\\?*!&]+$");
    //QRegExp exp("[^ /\\?*!&]+[.][a-zA-Z]{2,5}$");
    //QRegExp exp("([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\\-]*[A-Za-z0-9]");
    return exp.exactMatch(host);
}


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}

