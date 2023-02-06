#ifndef MAINWINDOW_CPP
#define MAINWINDOW_CPP

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDialog>
#include <QProcess>
#include <QStringList>
#include <QRegExp>
#include <QUrl>
#include <QToolBar>
#include <QHostInfo>
#include <QLabel>
#include <QScrollBar>
#include <signal.h>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QClipboard>
#include <QHostAddress>
#include <QAbstractSocket>
#include <QButtonGroup>
#include <QNetworkInterface>
#include <unistd.h>

#include <QDebug>


extern bool isIP( QString ip);
extern bool isHostname( QString host);


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi( this);
    ui->UserInput->setFocus();


    QSettings::setDefaultFormat( QSettings::IniFormat);
    settings = new QSettings( "tetja.de", "mndc", this);

    //Window Settings
    //commented to test first appereance
    restoreGeometry(settings->value("Mainwindow/geometry").toByteArray());
    restoreState(settings->value("Mainwindow/windowState").toByteArray());

    authTries    = 0;
    maxAuthTries = settings->value("auth/maxAuthTries", 3).toInt();

    //Setting Up config
    config.insert("path/traceroute",  settings->value( "path/traceroute",  "traceroute").toString());
    config.insert("path/ping",        settings->value( "path/ping",        "ping").toString());
    config.insert("path/ping6",       settings->value( "path/ping6",       "ping").toString());
    config.insert("path/whois",       settings->value( "path/whois",       "whois").toString());
    config.insert("path/dig",         settings->value( "path/dig",         "dig").toString());
    config.insert("path/ssh",         settings->value( "path/ssh",         "ssh").toString());
    config.insert("path/nmap",        settings->value( "path/nmap",        "nmap").toString());
    config.insert("path/sudo",        settings->value( "path/sudo",        "sudo").toString());

    config.insert("options/traceroute",  settings->value( "options/traceroute",  "").toString());
    config.insert("options/ping",        settings->value( "options/ping",        "-4").toString());
    config.insert("options/ping6",       settings->value( "options/ping6",       "-6").toString());
    config.insert("options/whois",       settings->value( "options/whois",       "").toString());
    config.insert("options/dig",         settings->value( "options/dig",         "").toString());
    config.insert("options/ssh",         settings->value( "options/ssh",         "").toString());
    config.insert("options/nmap",        settings->value( "options/nmap",        "").toString());
    config.insert("options/sudo",        settings->value( "options/sudo",        "").toString());

    config.insert("nmcUrl",      settings->value("nmc/nmcUrl", "https://nmc.manitu.net/macaddress-lookup/index.php?action=lookup&macaddress=%TARGET%&lookup=Lookup").toString());
    config.insert("nmcUser",     settings->value("nmc/nmcUser", "nmc").toString());
    config.insert("nmcPassword", settings->value("nmc/nmcPassword", "").toString());

    Actions = new QActionGroup( this);
    Actions->addAction( ui->actionMX);
    Actions->addAction( ui->actionPing);
    Actions->addAction( ui->actionTraceroute);
    Actions->addAction( ui->actionWhois);
    Actions->addAction( ui->actionDig);
    Actions->addAction( ui->actionSSH);
    Actions->addAction( ui->actionMAC_to_Switch_Port);
    Actions->addAction( ui->actionNMap);
    Actions->setExclusive( true);
    ui->actionDig->setChecked( true);

    protoActions = new QActionGroup( this);
    protoActions->addAction( ui->actionAuto);
    protoActions->addAction( ui->actionIPv4);
    protoActions->addAction( ui->actionIPv6);
    protoActions->setExclusive( true);
    ui->actionAuto->setChecked( true);

    digActions = new QActionGroup( this);
    digActions->addAction( ui->actionA);
    digActions->addAction( ui->actionAAAA);
    digActions->addAction( ui->actionANY);
    digActions->addAction( ui->actionTXT);
    digActions->addAction( ui->actionPTR);
    digActions->addAction( ui->actionSRV);
    digActions->addAction( ui->actionMX);
    digActions->setExclusive( true);

    digRadioButtons = new QButtonGroup( this);
    digRadioButtons->addButton(ui->digA);
    digRadioButtons->addButton(ui->digAAAA);
    digRadioButtons->addButton(ui->digANY);
    digRadioButtons->addButton(ui->digTXT);
    digRadioButtons->addButton(ui->digPTR);
    digRadioButtons->addButton(ui->digSRV);
    digRadioButtons->addButton(ui->digMX);
    digRadioButtons->setExclusive( true);

    sshUser = new QActionGroup( this);
    sshUser->addAction( ui->actionCurrent_User);
    sshUser->addAction( ui->actionRoot);
    sshUser->addAction( ui->actionAsk);

    ui->tracerouteProtocol->addItem("ICMP");
    ui->tracerouteProtocol->addItem("UDP");
    ui->tracerouteProtocol->addItem("TCP");

    ui->digNameserver->addItem("System");

    ui->whoisServer->addItem("Auto");

    QLabel *statusLabel = new QLabel( this);
    statusLabel->setObjectName("statusLabel");
    statusBar()->addPermanentWidget( statusLabel);

    worker = new QProcess( this);
    QObject::connect( worker, SIGNAL( readyRead()), this, SLOT(updateOutput()));
    QObject::connect( worker, SIGNAL( stateChanged( QProcess::ProcessState)), this, SLOT( workerStatusChanged()));
    QObject::connect( worker, SIGNAL( error( QProcess::ProcessError)), this, SLOT( workerError( QProcess::ProcessError)));

    nam = new QNetworkAccessManager(this);
    QObject::connect( nam, SIGNAL(finished(QNetworkReply*)), this, SLOT(updateOutputBrowser(QNetworkReply*)));
    QObject::connect( nam, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)), this, SLOT(ignoreSslError(QNetworkReply*)));
    QObject::connect( nam, SIGNAL(authenticationRequired(QNetworkReply*,QAuthenticator*)), this, SLOT(Authenticate(QNetworkReply*,QAuthenticator*)));

    QObject::connect( ui->UserInput, SIGNAL(returnPressed()),this,SLOT( runAction()));
    QObject::connect( ui->UserInput, SIGNAL(returnPressed()),this,SLOT( updateAdditionalInformation()));

    QObject::connect( ui->status, SIGNAL(clicked()), this, SLOT( buttonPressed()));

    QObject::connect( ui->Output, SIGNAL(anchorClicked( QUrl)), this, SLOT( newTarget( QUrl)));

    QObject::connect( this, SIGNAL(changedTarget()), this, SLOT( runAction()));
    QObject::connect( this, SIGNAL(changedTarget()), this, SLOT( updateAdditionalInformation()));

    QObject::connect( ui->back, SIGNAL( clicked()), this, SLOT( oneTargetBack()));
    QObject::connect( ui->Forward, SIGNAL( clicked()), this, SLOT( oneTargetForward()));

    //QObject::connect( this->Actions, SIGNAL(triggered(QAction*)), this, SLOT(runAction()));
    QObject::connect( ui->Start, SIGNAL( clicked()), this, SLOT( runAction()));
    QObject::connect( ui->Start, SIGNAL( clicked()), this,SLOT( updateAdditionalInformation()));

    //Change Options Pane
    QObject::connect( this->Actions, SIGNAL(triggered(QAction*)), this, SLOT(changeOptionPane()));

    QObject::connect( ui->actionEinf_gen, SIGNAL( triggered()), this, SLOT( pasteEingabe()));
    QObject::connect( ui->actionEinstellungen, SIGNAL(triggered()), this, SLOT(alterSettings()));

    QObject::connect( ui->actionNew_Window, SIGNAL(triggered()), this, SLOT(NewInstance()));

    clipboard = QApplication::clipboard();
    QObject::connect( clipboard, SIGNAL( changed(QClipboard::Mode)), this, SLOT(updateClipboardFields()));
    QObject::connect( ui->buttonInsertClipboard, SIGNAL(clicked()), this, SLOT(insertClipboard()));
    QObject::connect( ui->buttonInsertMouseSelection, SIGNAL(clicked()), this, SLOT(insertMouseSelection()));


    this->updateClipboardFields();
    changeOptionPane();

    interfaceNames.append("Auto");
    QList<QNetworkInterface> allInterfaces = QNetworkInterface::allInterfaces ();
    QNetworkInterface interface;
    foreach( interface, allInterfaces) {
        interfaceNames.append(interface.humanReadableName());
    }

    ui->pingInterface->addItems(interfaceNames);
    ui->tracerouteInterface->addItems(interfaceNames);

}

MainWindow::~MainWindow()
{
    worker->close();
    worker->kill();

    settings->setValue("Mainwindow/geometry", saveGeometry());
    settings->setValue("Mainwindow/windowState", saveState());

    delete ui;
}

void MainWindow::changeOptionPane()
{
    QString Action = this->Actions->checkedAction()->text().toLower().replace("&","");
    if ( Action == "ping") {
        ui->optionPane->setCurrentIndex(0);
    } else if ( Action == "traceroute") {
        ui->optionPane->setCurrentIndex(1);
    } else if ( Action == "whois") {
        ui->optionPane->setCurrentIndex(2);
    } else if ( Action == "dig") {
        ui->optionPane->setCurrentIndex(3);
    } else if ( Action == "nmap") {
        ui->optionPane->setCurrentIndex(4);
    }
}

void MainWindow::runAction()
{
    QString target  = ui->UserInput->text().trimmed();

    if ( lastTargets.isEmpty() || (lastTargets.last() !=  target) ) lastTargets.append( target);
    if ( lastTargets.count() > 1) ui->back->setEnabled(true);
    else ui->back->setEnabled(false);

    QStringList args;
    QString Action = this->Actions->checkedAction()->text().toLower().replace("&","");
    this->runningAction = Action;
    if ( Action == "ping" || Action == "traceroute") {
        switch(doIPv4orIPv6(target)) {
        case DUNNO:

        case DoIPv4:
            break;

        case DoIPv6:
            if ( Action == "ping") Action = Action+"6";
            if ( Action == "traceroute") args.append("-6");
            break;
        }

        if ( Action == "traceroute") args.append(tracerouteOptions());
        if ( Action == "ping" || Action == "ping6") args.append(pingOptions());

        args.append(target);
        startExternalCommand(actionToPath(Action), args);

    } else if ( Action == "whois") {
        startExternalCommand(actionToPath("whois"), QUrl::toAce(target));
        args.append(whoisOptions());

    }
    else if ( Action == "ssh") {
        QProcess *tProc = new QProcess( this);
        args << "-l" << this->sshUser->checkedAction()->text().trimmed() << target;
        tProc->start( actionToPath("ssh"), args);

    }
    else if ( Action == "dig"  )
    {
        Action = this->digActions->checkedAction()->text().toLower().replace("&","");
        if (ui->digNameserver->currentText() != "System") args.append("@"+ui->digNameserver->currentText());
        QString temp = ui->digAdditionalOptions->text();
        if (temp != "") args.append(temp.split(' '));
        // Must be last before IP
        if ( Action == "ptr" ) args << "-x";
        args << target << Action;
        startExternalCommand(actionToPath("dig"), args);

    }
    else if ( Action == "mac-to-switch-port" )
    {
        authTries = 0;
        QNetworkRequest request;
        request.setUrl(QUrl(QString(config.value("nmcUrl")).replace("%TARGET%", target)));
        nam->get(request);
    }
    else if ( Action == "nmap")
    {
        switch(doIPv4orIPv6(target)) {
        case DUNNO:

        case DoIPv4:
            break;

        case DoIPv6:
            args << "-6";
            break;
        }
        args << target << nmapOptions();
        startExternalCommand(actionToPath("nmap"), args);
    }
}

QStringList MainWindow::nmapOptions() 
{
    QStringList arg;

    if (ui->nmapVerbose->checkState()) arg.append("-vv");
    if (ui->nmapOsDetection->checkState()) arg.append("-O");
    if (ui->nmapUseDns->checkState()) arg.append("-n");
    if (ui->nmapServiceVersion->checkState()) arg.append("-sV");

    QString temp;
    switch (ui->nmapDiscoveryMode->currentIndex()) 
    {
        case 0: arg << "-PS"; break;
        case 1: arg << "-PA"; break;
        case 2: arg << "-PU"; break;
        case 3: arg << "-PE"; break;
        case 4: arg << "-PN"; break;
    }

    switch (ui->nmapScanTechnique->currentIndex()) 
    {
        case 0: arg << "-sS"; break;
        case 1: arg << "-sT"; break;
        case 2: arg << "-sA"; break;
        case 3: arg << "-sW"; break;
        case 4: arg << "-sM"; break;
        case 5: arg << "-sU"; break;
        case 6: arg << "-sN"; break;
        case 7: arg << "-sF"; break;
        case 8: arg << "-sX"; break;
        case 9: arg << "-s0"; break;
        case 10: arg << "-b"; break;
    }

    if (ui->nmapFastScan->isChecked()) arg << "-F";
    else if(ui->nmapPortRange->isChecked()) arg << "-p" << ui->nmapPortRangeInput->text();

    return arg;
}

QStringList MainWindow::tracerouteOptions() 
{
    QStringList arg;
    if (ui->tracerouteInterface->currentText() != "Auto") arg.append("--interface="+ui->tracerouteInterface->currentText());

    if (ui->tracerouteProtocol->currentText() == "UDP") arg.append("--udp");
    else if (ui->tracerouteProtocol->currentText() == "TCP") arg.append("--tcp");

    QString temp;
    arg.append( "--first="+temp.setNum(ui->traceroute1stTTL->value()));
    arg.append( "--max-hops="+temp.setNum(ui->tracerouteMaxTTL->value()));
    arg.append( "--wait="+temp.setNum(ui->tracerouteWaittime->value()));
    arg.append( "--queries="+temp.setNum(ui->tracerouteProbesPerHop->value()));

    if (ui->traceroutePrintAS->checkState()) arg.append("--as-path-lookups");
    if (!ui->tracerouteResolveNames->checkState()) arg.append("-n");

    temp = ui->tracerouteAdditionalOptions->text();
    if (ui->tracerouteAdditionalOptions->text() != "") arg.append(temp.split(' '));

    return arg;
}

QStringList MainWindow::pingOptions() 
{
    QStringList arg;
    if (ui->pingInterface->currentText() != "Auto") arg.append("-I "+ui->pingInterface->currentText());

    QString temp;
    temp.setNum(ui->pingCount->value());
    if (temp != "0") arg.append("-c "+temp.setNum(ui->pingCount->value()));
    arg.append("-i "+temp.setNum(ui->pingInterval->value()));

    // Summary Interval Handler ist missing

    temp = ui->pingAdditionalOptions->text();
    if (ui->pingAdditionalOptions->text() != "") arg.append(temp.split(' '));

    return arg;

}


QStringList MainWindow::whoisOptions() 
{
    QStringList arg;

    if (ui->whoisServer->currentText() != "Auto") arg.append("-h " + ui->whoisServer->currentText());
    if (!ui->whoisDisclaimer->checkState()) arg.append("-H");

    return arg;
}

MainWindow::IPv4orIPv6 MainWindow::doIPv4orIPv6(QString target)
{
    qint8 ipv4=0;
    qint8 ipv6=0;

    QList<QHostAddress> adresses = QHostInfo::fromName(target).addresses();
    QHostAddress address;
    foreach(address, adresses)  {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) ipv4=1;
        else if (address.protocol() == QAbstractSocket::IPv6Protocol) ipv6=1;
    }

    if      (ui->actionAuto->isChecked() && ipv6) return DoIPv6;
    else if (ui->actionAuto->isChecked() && ipv4) return DoIPv4;
    else if (ui->actionIPv6->isChecked())         return DoIPv6;
    else if (ui->actionIPv4->isChecked())         return DoIPv4;
    return DUNNO;
}

void MainWindow::startExternalCommand( QString cmd, QString arg)
{
    QStringList sl;
    if ( arg != "" ) sl.append(arg);
    startExternalCommand( cmd, sl);
}

void MainWindow::startExternalCommand( QString cmd, QStringList args)
{
    out.clear();
    ui->Output->clear();
    worker->close();
    worker->waitForFinished(1000);
    if (worker->state() != QProcess::NotRunning) worker->kill();

    //Use sudo if we want root
    // TODO: Make sudo configurable
    if (ui->actionDo_as_root->isChecked())
    {
        args.prepend(cmd);
        cmd = actionToPath("sudo");
    }

    worker->start( cmd, args);
    if (worker->waitForFinished(1000))
    {
        ui->Output->append(QString::fromLocal8Bit(worker->readAllStandardError()));
    } else if ( worker->state() != QProcess::Running ) ui->Output->append(tr("Process couldn't be started!"));
}

void MainWindow::updateOutput()
{
    out.append( QString::fromLocal8Bit(worker->readAll()).toUtf8());
    
    if (this->runningAction == "ping" || this->runningAction == "ping6") kill(worker->processId(), SIGQUIT);
    out.append( QString::fromLocal8Bit(worker->readAllStandardError()).toUtf8());

    QString formatted = (QString)out;
    formatted = markupOutput( formatted, QRegExp(QString("\\b((\\w|\\w+[-\\w]*\\w+)\\.)+([A-Za-z]{2,26})\\b")), QString("hostname"), QString("<a href='%PLACEHOLDER%'>"), QString("</a>"), 0);
    formatted = markupOutput( formatted, QRegExp(QString("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})[: \\t\\n)]")), QString("ip"), QString("<a href='%PLACEHOLDER%'>"), QString("</a>"), 1);
    formatted = markupOutput( formatted, QRegExp(QString("\\b(([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6})|(([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5})|(([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4})|(([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3})|(([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2})|(([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1})|((([0-9a-f]{1,4}:){1,7}|:):)|(:(:[0-9a-f]{1,4}){1,7})|(((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}))|((([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}))|(([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|(([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|(([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|(([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|(([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|((([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})|(:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3})[ \\t\\n)]")), QString("ipv6"), QString("<a href='%PLACEHOLDER%'>"), QString("</a>"), 0);

    formatted.replace("\n", "<br/>\n");
    formatted.prepend("<HTML><BODY>");
    formatted.append("</BODY></HTML>");

    ui->Output->setHtml( formatted);

    // Keep Scrolling with Output
    QScrollBar *sb = ui->Output->verticalScrollBar();
    sb->setValue( sb->maximum());
}

void MainWindow::updateOutputBrowser(QNetworkReply* reply)
{
    out.clear();
    ui->Output->clear();
    if (reply->error() > QNetworkReply::NoError)
    {
        out.append( (reply->errorString()+"\n").toUtf8());
    }
    out.append( reply->readAll() );

    ui->Output->append( (QString)out);

    ui->Output->update();
}

QString MainWindow::markupOutput( QString out, QRegExp re, QString scheme, QString before, QString after, int cap = 0)
{
    QRegExp expand("%PLACEHOLDER%");
    int pos = 0;
    QString before_expanded = "";
    QString scheme_expanded = scheme + "://";
    //scheme_expanded.append("://");
    QString tmpString;
    while (( pos = re.indexIn( out, pos)) != -1)
    {
        before_expanded = before;
        tmpString = scheme_expanded;
        if ( scheme == "ipv6") tmpString.append("[");
        tmpString.append( re.cap( cap));
        if ( scheme == "ipv6") tmpString.append("]");
        before_expanded.replace( expand, tmpString);

        out.insert( pos, before_expanded);
        out.insert( pos + before_expanded.length() + re.cap( cap).length(), after);

        pos += re.matchedLength() + before_expanded.length() + after.length();
    }
    return out;
}

void MainWindow::workerStatusChanged()
{
    if ( this->worker->state() == QProcess::NotRunning)
    {
        ui->status->setEnabled(false);
    } else if ( this->worker->state() >= QProcess::Starting)
    {
        ui->status->setEnabled(true);
    }
}

void MainWindow::buttonPressed()
{
    if ( this->worker->state() >= QProcess::Starting)
    {
        //Todo: implement Action Specific stops
#ifndef WINDOWS
        kill( worker->processId(), SIGINT);
        sleep( 1);
#endif
        worker->terminate();
        updateOutput();
    }
    worker->kill();
}

void MainWindow::newTarget(QUrl url)
{
    ui->UserInput->setText( url.host());
    ui->UserInput->update();
    emit changedTarget();
}

void MainWindow::updateAdditionalInformation()
{
    QHostInfo hInfo = QHostInfo::fromName(ui->UserInput->text());
    QString output = tr("Hostname: %HOSTNAME% IP-Adress: %IP%");
    QString hostname = hInfo.hostName();
    QString ip = "";
    if (!hInfo.addresses().empty()) ip = hInfo.addresses().first().toString();
    output.replace("%HOSTNAME%", hostname);
    output.replace("%IP%", ip);
    QLabel *statusLabel = statusBar()->findChild<QLabel *>("statusLabel");
    statusLabel->setText( output);
    statusLabel->update();
}

void MainWindow::workerError(QProcess::ProcessError pe)
{
    QString error;
    //ui->Output->append("An Error Ocurred!");
    switch(pe)
    {
        case QProcess::FailedToStart:  error="QProcess::FailedToStart"; break;
        case QProcess::Crashed:        error="QProcess::Crashed"; break;
        case QProcess::UnknownError:   error="QProcess::UnknownError"; break;
        default:                       error="Some Error"; break;
    }
    //ui->Output->append(error);
    ui->Output->append(worker->readAllStandardError());
}

void MainWindow::oneTargetBack()
{
    if ( lastTargets.count() < 2) return;
    nextTargets.append( lastTargets.last());
    lastTargets.removeLast();
    QString back = lastTargets.last();
    QUrl url;
    url.setHost( back);
    lastTargets.removeLast();
    ui->Forward->setEnabled( true);
    newTarget( url);
}

void MainWindow::oneTargetForward()
{
    if ( ! nextTargets.isEmpty())
    {
        QString next = nextTargets.last();
        QUrl url;
        url.setHost( next);
        nextTargets.removeLast();
        newTarget( url);
    }
    if ( nextTargets.isEmpty()) ui->Forward->setEnabled( false);
}

void MainWindow::pasteEingabe()
{
    ui->UserInput->clear();
    ui->UserInput->paste();
}

void MainWindow::alterSettings()
{
    Preferences prefs;
    prefs.setConfig( config);
    if (prefs.exec() == QDialog::Accepted) {
        config = prefs.getConfig();
    }
    settings->setValue( "path/traceroute",  config.value("path/traceroute"));
    settings->setValue( "path/ping",        config.value("path/ping"));
    settings->setValue( "path/ping6",       config.value("path/ping6"));
    settings->setValue( "path/dig",         config.value("path/dig"));
    settings->setValue( "path/whois",       config.value("path/whois"));
    settings->setValue( "path/ssh",         config.value("path/ssh"));
    settings->setValue( "path/nmap",        config.value("path/nmap"));
    settings->setValue( "path/sudo",        config.value("path/sudo"));

    settings->setValue( "options/traceroute",  config.value("options/traceroute"));
    settings->setValue( "options/ping",        config.value("options/ping"));
    settings->setValue( "options/ping6",       config.value("options/ping6"));
    settings->setValue( "options/dig",         config.value("options/dig"));
    settings->setValue( "options/whois",       config.value("options/whois"));
    settings->setValue( "options/ssh",         config.value("options/ssh"));
    settings->setValue( "options/nmap",        config.value("options/nmap"));
    settings->setValue( "options/sudo",        config.value("options/sudo"));

    settings->setValue( "nmc/nmcUrl",      config.value("nmcUrl"));
    settings->setValue( "nmc/nmcUser",     config.value("nmcUser"));
    settings->setValue( "nmc/nmcPassword", config.value("nmcPassword"));
}

void MainWindow::ignoreSslError(QNetworkReply* reply)
{
    reply->ignoreSslErrors();
}

void MainWindow::Authenticate(QNetworkReply* reply, QAuthenticator* auth)
{
    if (authTries++ <= maxAuthTries) {
        auth->setPassword(config.value("nmcPassword"));
        auth->setUser(config.value("nmcUser"));
    } else reply->abort();
}

void MainWindow::NewInstance() 
{
    MainWindow* w = new MainWindow();
    w->show();
}

QString MainWindow::actionToPath(QString cmd)
{
    //TODO: add some error handling
    return config.value("path/"+cmd);
}

void MainWindow::updateClipboardFields()
{
    ui->buttonInsertClipboard->setText( clipboard->text(QClipboard::Clipboard).trimmed().left(60).replace("\n", " "));
    ui->buttonInsertMouseSelection->setText( clipboard->text(QClipboard::Selection).trimmed().left(60).replace("\n", " "));
}

void MainWindow::insertMouseSelection()
{
    ui->UserInput->setText( clipboard->text(QClipboard::Selection));
}

void MainWindow::insertClipboard()
{
    ui->UserInput->setText( clipboard->text(QClipboard::Clipboard));
}

#endif
