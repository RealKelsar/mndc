#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtWidgets/QMainWindow>
#include <QProcess>
#include <QString>
#include <QUrl>
#include <QActionGroup>
#include <QAction>
#include <QSettings>
#include "preferences.h"
#include <QNetworkAccessManager>
#include <QAuthenticator>
#include <QButtonGroup>
#include <QClipboard>

namespace Ui
{
    class MainWindow;

}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QProcess *worker;
    QByteArray out;
    QStringList lastTargets;
    QStringList nextTargets;
    QActionGroup *Actions;
    QActionGroup *digActions;
    QActionGroup *sshUser;
    QActionGroup *protoActions;
    QButtonGroup *digRadioButtons;
    QSettings *settings;
    QNetworkAccessManager *nam;
    QStringList interfaceNames;
    QClipboard *clipboard;
    QString runningAction;

    qint32 authTries;
    qint32 maxAuthTries;

    QHash<QString, QString> config;

    QString markupOutput( QString out, QRegExp re, QString scheme, QString before, QString after, int cap);
    void startExternalCommand( QString cmd, QStringList args);
    void startExternalCommand( QString cmd, QString arg);

    QStringList pingOptions();
    QStringList tracerouteOptions();
    QStringList whoisOptions();
    QStringList nmapOptions();

    QString actionToPath(QString cmd);

    //    QStringList expandOptions( QString);

    enum IPv4orIPv6 {DUNNO, DoIPv4, DoIPv6};
    IPv4orIPv6 doIPv4orIPv6(QString target);

signals:
    void changedTarget();

public slots:
    void updateOutput();
    void updateOutputBrowser(QNetworkReply*);
    void workerStatusChanged();
    void buttonPressed();
    void newTarget(QUrl);
    void updateAdditionalInformation();
    void workerError(QProcess::ProcessError);
    void runAction();
    void oneTargetBack();
    void oneTargetForward();
    void pasteEingabe();
    void alterSettings();
    void ignoreSslError(QNetworkReply*);
    void Authenticate(QNetworkReply*, QAuthenticator*);
    //void changeDefaultAction();
    void changeOptionPane();
    void NewInstance();
    void insertClipboard();
    void insertMouseSelection();
    void updateClipboardFields();

};

#endif // MAINWINDOW_H
