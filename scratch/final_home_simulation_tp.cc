// final_home_simulation_tp_fixed.cc
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/config-store.h"
#include "ns3/global-value.h"

#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <set>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("GenerationDatasetIoT");

// Structure pour définir le profil d'un équipement
struct DeviceProfile {
    std::string name;       // Ex: "CameraHD"
    std::string protocol;   // "UDP" ou "TCP"
    std::string dataRate;   // Débit d'envoi (Ex: "2Mbps")
    uint32_t packetSize;    // Taille du paquet applicatif
    double onTimeMean;      // Temps moyen d'activité (s)
    double offTimeMean;     // Temps moyen de silence (s)
    uint16_t port;          // Port de destination
};

int main (int argc, char *argv[])
{
    uint32_t nPerType = 15;     // Nombre d'appareils par type
    double simulationTime = 600.0;
    double simTime = 300.0;     // Durée (5 minutes pour avoir assez d'historique)
    bool verbose = false;

    CommandLine cmd (__FILE__);
    cmd.AddValue ("nPerType", "Nombre d'équipements par type", nPerType);
    cmd.AddValue ("simTime", "Durée de la simulation (s) (unused variable kept)", simTime);
    cmd.AddValue ("verbose", "Activer les logs", verbose);
    cmd.Parse (argc, argv);

    // ** IMPORTANT ** : Ne pas appeler Config::SetDefault sur des attributs inexistants (provoque NS_FATAL).
    // Config::SetDefault ("ns3::PcapHelperForDevice::PacketLimit", UintegerValue (0)); // supprimé (incompatible)

    if (verbose) {
        LogComponentEnable ("GenerationDatasetIoT", LOG_LEVEL_INFO);
    }

    // --- 2. Définition des 25 Profils (Variabilité) ---
    std::vector<DeviceProfile> profiles = {
        // Haut Débit / Multimédia
        {"SmartTV_4K", "UDP", "15Mbps", 1400, 50.0, 0.1, 5001},
        {"IP_Camera_HD", "UDP", "4Mbps", 1400, 20.0, 0.5, 5002},
        {"Laptop_Download", "TCP", "50Mbps", 1460, 5.0, 2.0, 80},
        {"Game_Console", "UDP", "1Mbps", 200, 0.5, 0.5, 3074},
        {"VR_Headset", "UDP", "20Mbps", 1000, 2.0, 0.1, 5003},

        // Bureautique / Web
        {"Smartphone_Web", "TCP", "2Mbps", 800, 1.0, 5.0, 443},
        {"Tablet_VideoCall", "UDP", "1.5Mbps", 1000, 10.0, 1.0, 3478},
        {"Smart_Speaker", "TCP", "320Kbps", 500, 30.0, 1.0, 8080},
        {"Printer", "TCP", "500Kbps", 1000, 2.0, 60.0, 631},
        {"NAS_Backup", "TCP", "10Mbps", 1460, 10.0, 60.0, 445},

        // IoT Domotique (Sporadique)
        {"Thermostat", "TCP", "1Kbps", 100, 0.5, 300.0, 80},
        {"Smart_Bulb", "UDP", "500bps", 50, 0.1, 60.0, 5683}, // CoAP style
        {"Smart_Plug", "TCP", "1Kbps", 150, 0.5, 60.0, 1883}, // MQTT style
        {"Door_Lock", "TCP", "2Kbps", 200, 0.2, 3600.0, 8883},
        {"Smoke_Detector", "UDP", "200bps", 40, 0.1, 3600.0, 5004},

        // Capteurs Environnement (Très faible débit)
        {"Temp_Sensor", "UDP", "100bps", 32, 0.1, 60.0, 1883},
        {"Humidity_Sensor", "UDP", "100bps", 32, 0.1, 60.0, 1883},
        {"Motion_Sensor", "UDP", "1Kbps", 64, 0.1, 30.0, 5005},
        {"Light_Sensor", "UDP", "100bps", 32, 0.1, 120.0, 5683},
        {"AirQuality_Mon", "TCP", "500bps", 100, 0.5, 300.0, 8080},

        // Electroménager Connecté
        {"Fridge", "TCP", "2Kbps", 200, 1.0, 600.0, 80},
        {"Washing_Machine", "TCP", "1Kbps", 150, 1.0, 120.0, 80},
        {"Robot_Vacuum", "UDP", "50Kbps", 500, 5.0, 60.0, 1234},
        {"Oven", "TCP", "1Kbps", 100, 0.5, 600.0, 80},
        {"Coffee_Maker", "TCP", "500bps", 100, 0.2, 3600.0, 80}
    };

    uint32_t nTypes = profiles.size();
    uint32_t totalSta = nTypes * nPerType;

    NS_LOG_INFO ("Configuration : " << nTypes << " types, " << totalSta << " équipements au total.");

    // --- 3. Configuration Réseau (Wifi 802.11ac) ---
    NodeContainer wifiStaNodes;
    wifiStaNodes.Create (totalSta);
    NodeContainer wifiApNode;
    wifiApNode.Create (1);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    YansWifiPhyHelper phy;
    phy.SetChannel (channel.Create ());

    // Configuration MAC
    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211ac); // Haute capacité pour supporter 375 noeuds

    WifiMacHelper mac;
    Ssid ssid = Ssid ("SmartHome_Dataset_Gen");

    // AP
    mac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid));
    NetDeviceContainer apDevices = wifi.Install (phy, mac, wifiApNode);

    // STA
    mac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid), "ActiveProbing", BooleanValue (false));
    NetDeviceContainer staDevices = wifi.Install (phy, mac, wifiStaNodes);

    // --- 4. Mobilité (Grid pour éviter les superpositions) ---
    MobilityHelper mobility;

    Ptr<ConstantPositionMobilityModel> apMobility = CreateObject<ConstantPositionMobilityModel> ();
    apMobility->SetPosition (Vector (80.0, 80.0, 0.0)); // Placé au centre (X=80, Y=80)
    wifiApNode.Get (0)->AggregateObject (apMobility); // Installe le modèle sur l'AP

    mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                   "MinX", DoubleValue (0.0), "MinY", DoubleValue (0.0),
                                   "DeltaX", DoubleValue (8.0), "DeltaY", DoubleValue (8.0),
                                   "GridWidth", UintegerValue (20),
                                   "LayoutType", StringValue ("RowFirst"));

    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (wifiStaNodes);

    // --- 5. Pile IP ---
    InternetStackHelper stack;
    stack.Install (wifiApNode);
    stack.Install (wifiStaNodes);

    Ipv4AddressHelper address;
    address.SetBase ("192.168.0.0", "255.255.252.0"); // /22 pour supporter > 254 hôtes
    Ipv4InterfaceContainer apInterfaces = address.Assign (apDevices);
    Ipv4InterfaceContainer staInterfaces = address.Assign (staDevices);

    // --- 6. Applications & Vérité Terrain (CSV) ---
    // Fichier CSV pour mapper IP -> Label (Indispensable pour le ML supervisé)
    std::ofstream labelFile;
    labelFile.open ("output/ground_truth.csv");
    labelFile << "NodeID,IP,DeviceType,Protocol,TrafficPattern\n";

    // Serveur "Sink" sur l'AP (reçoit tout le trafic) : un sink UDP et TCP pour chaque port
    std::set<uint16_t> usedPorts;
    for (const auto& p : profiles) usedPorts.insert(p.port);

    for (uint16_t port : usedPorts) {
        PacketSinkHelper sinkUdp ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
        sinkUdp.Install (wifiApNode.Get (0));
        PacketSinkHelper sinkTcp ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
        sinkTcp.Install (wifiApNode.Get (0));
    }

    // Source Applications sur les STAs
    RngSeedManager::SetSeed (12345);
    RngSeedManager::SetRun (1);
    Ptr<UniformRandomVariable> startRng = CreateObject<UniformRandomVariable> ();
    startRng->SetAttribute ("Min", DoubleValue (0.0));
    startRng->SetAttribute ("Max", DoubleValue (5.0)); // Démarrage aléatoire 0-5s

    uint32_t nodeIdx = 0;

    std::map<std::string, std::string> typeAbbreviations = {
        {"SmartTV_4K", "T"}, {"IP_Camera_HD", "C"}, {"Laptop_Download", "L"}, {"Game_Console", "G"}, {"VR_Headset", "V"},
        {"Smartphone_Web", "S"}, {"Tablet_VideoCall", "T"}, {"Smart_Speaker", "A"}, {"Printer", "P"}, {"NAS_Backup", "N"},
        {"Thermostat", "H"}, {"Smart_Bulb", "B"}, {"Smart_Plug", "U"}, {"Door_Lock", "D"}, {"Smoke_Detector", "F"},
        {"Temp_Sensor", "M"}, {"Humidity_Sensor", "H"}, {"Motion_Sensor", "O"}, {"Light_Sensor", "R"}, {"AirQuality_Mon", "Q"},
        {"Fridge", "R"}, {"Washing_Machine", "W"}, {"Robot_Vacuum", "R"}, {"Oven", "O"}, {"Coffee_Maker", "K"}
    };

    // Pour NetAnim
    AnimationInterface anim ("traces/smart_home_simulation.xml");
    anim.UpdateNodeDescription(wifiApNode.Get(0), "Access_Point");
    anim.UpdateNodeColor(wifiApNode.Get(0), 0, 255, 0); // Vert pour l'AP

    // Eviter que NetAnim stoppe l'écriture du XML en dépassant la limite :
    // on met une limite très grande (pratique pour très gros scénarios).
    anim.SetMaxPktsPerTraceFile (99999999999ULL);

    uint32_t typeIndex = 0;

    for (const auto& prof : profiles) {
        // Détermination des lettres d'abréviation
        std::string typeAbbr = prof.name.substr(0, 1); // Première lettre du Type (ex: S pour Smartphone)
        if (typeAbbreviations.count(prof.name)) {
            typeAbbr = typeAbbreviations.at(prof.name);
        }

        for (uint32_t i = 0; i < nPerType; ++i) {
            Ptr<Node> node = wifiStaNodes.Get (nodeIdx);
            Ipv4Address ip = staInterfaces.GetAddress (nodeIdx);

            // Génération du Nom NetAnim: [Lettre Type][Numéro Instance] (Ex: P3 pour Printer 3)
            std::string netanimName = typeAbbr + std::to_string(i + 1);

            // Enregistrement Vérité Terrain (labelFile inchangé)
            labelFile << node->GetId() << "," << ip << "," 
                      << prof.name << "," << prof.protocol << "," 
                      << "Variable" << "\n";

            // Configuration NetAnim (Nom)
            anim.UpdateNodeDescription(node, netanimName);
            // Couleur pseudo-aléatoire basée sur le type
            anim.UpdateNodeColor(node, (typeIndex * 50) % 255, (typeIndex * 20) % 255, (typeIndex * 80) % 255);

            // --- Applications OnOff (client) pointant vers l'AP ---
            std::string factory = (prof.protocol == "UDP") ? "ns3::UdpSocketFactory" : "ns3::TcpSocketFactory";
            OnOffHelper onoff (factory, Address ());

            InetSocketAddress remote (apInterfaces.GetAddress (0), prof.port);
            onoff.SetAttribute ("Remote", AddressValue (remote));
            onoff.SetAttribute ("DataRate", StringValue (prof.dataRate));
            onoff.SetAttribute ("PacketSize", UintegerValue (prof.packetSize));

            // OnTime / OffTime : ExponentialRandomVariable via StringValue (compatible ns-3.46.1)
            onoff.SetAttribute ("OnTime",
                StringValue ("ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.onTimeMean) + "]"));
            onoff.SetAttribute ("OffTime",
                StringValue ("ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.offTimeMean) + "]"));

            // Installer et démarrer l'application
            ApplicationContainer app = onoff.Install (node);
            double start = startRng->GetValue ();
            app.Start (Seconds (start));
            app.Stop (Seconds (simulationTime - 0.001));

            nodeIdx++;
        }
        typeIndex++;
    }
    labelFile.close();

    // --- 7. Tracing (PCAP sur l'AP uniquement pour éviter d'exploser le disque) ---
    // L'AP voit tout le trafic (uplink et downlink)
    phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
    phy.EnablePcap ("output/smart_home_simulation_capture", apDevices.Get (0), true);

    NS_LOG_INFO ("Simulation start...");

    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();
    Simulator::Destroy ();
    NS_LOG_INFO ("Done.");

    return 0;
}
