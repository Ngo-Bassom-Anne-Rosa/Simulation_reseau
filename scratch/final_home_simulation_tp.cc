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

struct DeviceProfile {
    std::string name;
    std::string category;
    std::string protocol;
    std::string dataRate;
    uint32_t packetSize;
    double onTimeMean;
    double offTimeMean;
    uint16_t port;
};

int main (int argc, char *argv[])
{
    uint32_t nPerType = 15;
    double simulationTime = 600.0;
    double simTime = 300.0;     
    bool verbose = false;

    CommandLine cmd (__FILE__);
    cmd.AddValue ("nPerType", "Nombre d'équipements par type", nPerType);
    cmd.AddValue ("simTime", "Durée de la simulation", simTime);
    cmd.AddValue ("verbose", "Activer les logs", verbose);
    cmd.Parse (argc, argv);

    if (verbose) {
        LogComponentEnable ("GenerationDatasetIoT", LOG_LEVEL_INFO);
    }

    std::vector<DeviceProfile> profiles = {

        {"SmartTV_4K", "Multimedia", "UDP", "15Mbps", 1400, 50.0, 0.1, 5001},
        {"IP_Camera_HD", "Multimedia", "UDP", "4Mbps", 1400, 20.0, 0.5, 5002},
        {"Laptop_Download", "Multimedia", "TCP", "50Mbps", 1460, 5.0, 2.0, 80},
        {"Game_Console", "Multimedia", "UDP", "1Mbps", 200, 0.5, 0.5, 3074},
        {"VR_Headset", "Multimedia", "UDP", "20Mbps", 1000, 2.0, 0.1, 5003},

        {"Smartphone_Web", "Bureautique", "TCP", "2Mbps", 800, 1.0, 5.0, 443},
        {"Tablet_VideoCall", "Bureautique", "UDP", "1.5Mbps", 1000, 10.0, 1.0, 3478},
        {"Smart_Speaker", "Bureautique", "TCP", "320Kbps", 500, 30.0, 1.0, 8080},
        {"Printer", "Bureautique", "TCP", "500Kbps", 1000, 2.0, 60.0, 631},
        {"NAS_Backup", "Bureautique", "TCP", "10Mbps", 1460, 10.0, 60.0, 445},

        {"Thermostat", "Domotique", "TCP", "1Kbps", 100, 0.5, 300.0, 80},
        {"Smart_Bulb", "Domotique", "UDP", "500bps", 50, 0.1, 60.0, 5683},
        {"Smart_Plug", "Domotique", "TCP", "1Kbps", 150, 0.5, 60.0, 1883},
        {"Door_Lock", "Domotique", "TCP", "2Kbps", 200, 0.2, 3600.0, 8883},
        {"Smoke_Detector", "Domotique", "UDP", "40bps", 200, 0.1, 3600.0, 5004},

        {"Temp_Sensor", "Capteurs", "UDP", "100bps", 32, 0.1, 60.0, 1883},
        {"Humidity_Sensor", "Capteurs", "UDP", "100bps", 32, 0.1, 60.0, 1883},
        {"Motion_Sensor", "Capteurs", "UDP", "1Kbps", 64, 0.1, 30.0, 5005},
        {"Light_Sensor", "Capteurs", "UDP", "100bps", 32, 0.1, 120.0, 5683},
        {"AirQuality_Mon", "Capteurs", "TCP", "500bps", 100, 0.5, 300.0, 8080},

        {"Fridge", "Electromenager", "TCP", "2Kbps", 200, 1.0, 600.0, 80},
        {"Washing_Machine", "Electromenager", "TCP", "1Kbps", 150, 1.0, 120.0, 80},
        {"Robot_Vacuum", "Electromenager", "UDP", "50Kbps", 500, 5.0, 60.0, 1234},
        {"Oven", "Electromenager", "TCP", "1Kbps", 100, 0.5, 600.0, 80},
        {"Coffee_Maker", "Electromenager", "TCP", "500bps", 100, 0.2, 3600.0, 80}
    };

    uint32_t nTypes = profiles.size();
    uint32_t totalSta = nTypes * nPerType;

    NodeContainer wifiStaNodes;
    wifiStaNodes.Create (totalSta);
    NodeContainer wifiApNode;
    wifiApNode.Create (1);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    YansWifiPhyHelper phy;
    phy.SetChannel (channel.Create ());

    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211ac);

    WifiMacHelper mac;
    Ssid ssid = Ssid ("SmartHome_Dataset_Gen");

    mac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid));
    NetDeviceContainer apDevices = wifi.Install (phy, mac, wifiApNode);

    mac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid), "ActiveProbing", BooleanValue (false));
    NetDeviceContainer staDevices = wifi.Install (phy, mac, wifiStaNodes);

    MobilityHelper mobility;
    Ptr<ConstantPositionMobilityModel> apMobility = CreateObject<ConstantPositionMobilityModel> ();
    apMobility->SetPosition (Vector (80.0, 80.0, 0.0));
    wifiApNode.Get (0)->AggregateObject (apMobility);

    mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                   "MinX", DoubleValue (0.0), "MinY", DoubleValue (0.0),
                                   "DeltaX", DoubleValue (8.0), "DeltaY", DoubleValue (8.0),
                                   "GridWidth", UintegerValue (20),
                                   "LayoutType", StringValue ("RowFirst"));
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (wifiStaNodes);

    InternetStackHelper stack;
    stack.Install (wifiApNode);
    stack.Install (wifiStaNodes);

    Ipv4AddressHelper address;
    address.SetBase ("192.168.0.0", "255.255.252.0");
    Ipv4InterfaceContainer apInterfaces = address.Assign (apDevices);
    Ipv4InterfaceContainer staInterfaces = address.Assign (staDevices);

    std::ofstream labelFile;
    labelFile.open ("output/ground_truth.csv");
    labelFile << "NodeID,IP,DeviceType,Protocol,TrafficPattern\n";

    std::set<uint16_t> usedPorts;
    for (const auto& p : profiles) usedPorts.insert(p.port);

    for (uint16_t port : usedPorts) {
        PacketSinkHelper sinkUdp ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
        sinkUdp.Install (wifiApNode.Get (0));
        PacketSinkHelper sinkTcp ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
        sinkTcp.Install (wifiApNode.Get (0));
    }

    RngSeedManager::SetSeed (12345);
    RngSeedManager::SetRun (1);
    Ptr<UniformRandomVariable> startRng = CreateObject<UniformRandomVariable> ();
    startRng->SetAttribute ("Min", DoubleValue (0.0));
    startRng->SetAttribute ("Max", DoubleValue (5.0));

    uint32_t nodeIdx = 0;

    std::map<std::string, std::string> typeAbbreviations = {
        {"SmartTV_4K", "T"}, {"IP_Camera_HD", "C"}, {"Laptop_Download", "L"}, {"Game_Console", "G"}, {"VR_Headset", "V"},
        {"Smartphone_Web", "S"}, {"Tablet_VideoCall", "A"}, {"Smart_Speaker", "P"}, {"Printer", "R"}, {"NAS_Backup", "N"},
        {"Thermostat", "H"}, {"Smart_Bulb", "B"}, {"Smart_Plug", "U"}, {"Door_Lock", "D"}, {"Smoke_Detector", "F"},
        {"Temp_Sensor", "M"}, {"Humidity_Sensor", "I"}, {"Motion_Sensor", "O"}, {"Light_Sensor", "R"}, {"AirQuality_Mon", "Q"},
        {"Fridge", "J"}, {"Washing_Machine", "W"}, {"Robot_Vacuum", "R"}, {"Oven", "O"}, {"Coffee_Maker", "K"}
    };

    std::map<std::string, char> categoryAbbreviations = {
        {"Multimedia", 'M'}, {"Bureautique", 'B'}, {"Domotique", 'D'}, 
        {"Capteurs", 'C'}, {"Electromenager", 'E'}
    };

    AnimationInterface anim ("output/smart_home_simulation.xml");
    anim.UpdateNodeDescription(wifiApNode.Get(0), "Access_Point");
    anim.UpdateNodeColor(wifiApNode.Get(0), 0, 255, 0);
    anim.SetMaxPktsPerTraceFile (99999999999ULL);

    uint32_t typeIndex = 0;

    for (const auto& prof : profiles) {
        char categoryAbbr = categoryAbbreviations.at(prof.category);
        std::string typeAbbr = typeAbbreviations.at(prof.name);
        
        for (uint32_t i = 0; i < nPerType; ++i) {
            Ptr<Node> node = wifiStaNodes.Get (nodeIdx);
            Ipv4Address ip = staInterfaces.GetAddress (nodeIdx);

            std::string netanimName = std::string(1, categoryAbbr) + "-" + typeAbbr + std::to_string(i + 1);

            labelFile << node->GetId() << "," << ip << "," 
                      << prof.name << "," << prof.protocol << "," 
                      << "OnOff_Exp" << "\n";

            anim.UpdateNodeDescription(node, netanimName);
            anim.UpdateNodeColor(node, (typeIndex * 50) % 255, (typeIndex * 20) % 255, (typeIndex * 80) % 255);

            std::string factory = (prof.protocol == "UDP") ? "ns3::UdpSocketFactory" : "ns3::TcpSocketFactory";
            OnOffHelper onoff (factory, Address ());

            InetSocketAddress remote (apInterfaces.GetAddress (0), prof.port);
            onoff.SetAttribute ("Remote", AddressValue (remote));
            onoff.SetAttribute ("DataRate", StringValue (prof.dataRate));
            onoff.SetAttribute ("PacketSize", UintegerValue (prof.packetSize));

            onoff.SetAttribute ("OnTime",
                StringValue ("ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.onTimeMean) + "]"));
            onoff.SetAttribute ("OffTime",
                StringValue ("ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.offTimeMean) + "]"));

            ApplicationContainer app = onoff.Install (node);
            double start = startRng->GetValue ();
            app.Start (Seconds (start));
            app.Stop (Seconds (simulationTime - 0.001));

            nodeIdx++;
        }
        typeIndex++;
    }
    labelFile.close();

    phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
    phy.EnablePcap ("output/smart_home_simulation_capture", apDevices.Get (0), true);

    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();
    Simulator::Destroy ();

    return 0;
}
