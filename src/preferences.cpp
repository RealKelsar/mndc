#include "preferences.h"
#include "ui_preferences.h"
#include <QFileDialog>
#include <QNetworkInterface>

Preferences::Preferences(QWidget *parent)
    : QDialog(parent), ui(new Ui::DialogSettings)
{
    ui->setupUi( this);

    QObject::connect( ui->buttonTraceroute,  SIGNAL(clicked()), this, SLOT(searchTraceroute()));
    QObject::connect( ui->buttonPing,        SIGNAL(clicked()), this, SLOT(searchPing()));
    QObject::connect( ui->buttonPing6,       SIGNAL(clicked()), this, SLOT(searchPing6()));
    QObject::connect( ui->buttonDig,         SIGNAL(clicked()), this, SLOT(searchDig()));
    QObject::connect( ui->buttonWhois,       SIGNAL(clicked()), this, SLOT(searchWhois()));
    QObject::connect( ui->buttonNmap,        SIGNAL(clicked()), this, SLOT(searchNmap()));
    QObject::connect( ui->buttonSudo,        SIGNAL(clicked()), this, SLOT(searchSudo()));

    updateNetworkConfig();
}

Preferences::~Preferences()
{
    delete ui;
}

void Preferences::setConfig( QHash<QString, QString> config)
{
    this->config = config;
    ui->inputDig->setText(         config.value("path/dig"));
    ui->inputPing->setText(        config.value("path/ping"));
    ui->inputTraceroute->setText(  config.value("path/traceroute"));
    ui->inputPing6->setText(       config.value("path/ping6"));
    ui->inputWhois->setText(       config.value("path/whois"));
    ui->inputNmap->setText(        config.value("path/nmap"));
    ui->inputSudo->setText(        config.value("path/sudo"));

    ui->inputDigOptions->setText(         config.value("options/dig"));
    ui->inputPingOptions->setText(        config.value("options/ping"));
    ui->inputTracerouteOptions->setText(  config.value("options/traceroute"));
    ui->inputPing6Options->setText(       config.value("options/ping6"));
    ui->inputWhoisOptions->setText(       config.value("options/whois"));
    ui->inputNmapOptions->setText(        config.value("options/nmap"));
    ui->inputSudoOptions->setText(        config.value("options/sudo"));

    ui->nmcUrl->setText(     config.value("nmcUrl"));
    ui->nmcUser->setText(    config.value("nmcUser"));
    ui->nmcPassword->setText(config.value("nmcPassword"));
}

void Preferences::setConfig()
{
    setConfig( config);
}

QHash<QString, QString> Preferences::getConfig()
{
    config.insert("path/dig",         ui->inputDig->text());
    config.insert("path/ping",        ui->inputPing->text());
    config.insert("path/traceroute",  ui->inputTraceroute->text());
    config.insert("path/ping6",       ui->inputPing6->text());
    config.insert("path/whois",       ui->inputWhois->text());
    config.insert("path/nmap",        ui->inputNmap->text());
    config.insert("path/sudo",        ui->inputSudo->text());

    config.insert("options/dig",         ui->inputDigOptions->text());
    config.insert("options/ping",        ui->inputPingOptions->text());
    config.insert("options/traceroute",  ui->inputTracerouteOptions->text());
    config.insert("options/ping6",       ui->inputPing6Options->text());
    config.insert("options/whois",       ui->inputWhoisOptions->text());
    config.insert("options/nmap",        ui->inputNmapOptions->text());
    config.insert("options/sudo",        ui->inputSudoOptions->text());

    config.insert("nmcUrl",      ui->nmcUrl->text());
    config.insert("nmcUser",     ui->nmcUser->text());
    config.insert("nmcPassword", ui->nmcPassword->text());

    return config;
}

void Preferences::updateNetworkConfig()
{
    ui->networkconfigOutput->clear();
    QString output = "";
    QList<QNetworkAddressEntry> addressEntrys;
    QNetworkAddressEntry addressEntry;
    QList<QNetworkInterface> allInterfaces = QNetworkInterface::allInterfaces ();
    QNetworkInterface interface;
    foreach( interface, allInterfaces) {
        output.append(interface.humanReadableName()+"\n");
        output.append("\tHardware Address: "+interface.hardwareAddress()+"\n");
        output.append("\tAddresses:\n");
        addressEntrys = interface.addressEntries();
        foreach( addressEntry, addressEntrys) {
            QString prefix;
            prefix.setNum(addressEntry.prefixLength());
            output.append("\t\tAddress: "+addressEntry.ip().toString()+"/"+prefix+(addressEntry.broadcast().protocol() == QAbstractSocket::IPv4Protocol?" Broadcast: "+addressEntry.broadcast().toString():"")+"\n");
        }
        output.append("\n");
    }
    ui->networkconfigOutput->setText(output);
}

void Preferences::searchTraceroute()
{
    search( "traceroute");
}

void Preferences::searchDig()
{
    search( "dig");
}

void Preferences::searchPing()
{
    search( "ping");
}

void Preferences::searchPing6()
{
    search( "ping6");
}

void Preferences::searchWhois()
{
    search( "whois");
}

void Preferences::searchNmap()
{
    search( "nmap");
}

void Preferences::searchSudo()
{
    search( "sudo");
}

void Preferences::search( QString Action)
{
    QString filter = Action + " (" + Action + ")";
    QString path = QFileDialog::getOpenFileName( this, Action, config.value(Action), filter);
    if ( ! path.isNull()) config.insert(Action, path);
    setConfig();
}
