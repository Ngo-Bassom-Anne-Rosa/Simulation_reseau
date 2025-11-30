#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include <fstream>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("MaisonConnecteeML");

struct DeviceProfile {
    std::string typeName;
    std::string trafficType;
    std::string protocol;
    uint16_t port;
    std::string dataRate;
    uint32_t packetSize;
    double onTimeMean;
    double offTimeMean;
    std::string cpuClass;
};

int main (int argc, char *argv[])
{
    uint32_t nTypes = 12;
    uint32_t nPerType = 2;
    uint32_t nSta = nTypes * nPerType;
    double simTime = 60.0;
    
    CommandLine cmd;
    cmd.Parse (argc, argv);

    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211ac);
    
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
    YansWifiPhyHelper wifiPhy;

    AsciiTraceHelper ascii;
    wifiPhy.EnableAsciiAll(ascii.CreateFileStream("traces/wifi-house-data.tr"));
    wifiPhy.SetChannel (wifiChannel.Create ());

    WifiMacHelper wifiMac;
    Ssid ssid = Ssid ("Home-AI-Network");

    NodeContainer apNode;
    apNode.Create (1);
    
    wifiMac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid));
    std::cout<<"Wifi set"<<std::endl;
    NetDeviceContainer apDevice = wifi.Install (wifiPhy, wifiMac, apNode);

    NodeContainer staNodes;
    staNodes.Create (nSta);
    
    wifiMac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid), "ActiveProbing", BooleanValue (false));
    NetDeviceContainer staDevices = wifi.Install (wifiPhy, wifiMac, staNodes);

    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                   "MinX", DoubleValue (0.0), "MinY", DoubleValue (0.0),
                                   "DeltaX", DoubleValue (2.0), "DeltaY", DoubleValue (2.0),
                                   "GridWidth", UintegerValue (5), "LayoutType", StringValue ("RowFirst"));
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (apNode);
    mobility.Install (staNodes);

    InternetStackHelper stack;
    stack.Install (apNode);
    stack.Install (staNodes);

    Ipv4AddressHelper address;
    address.SetBase ("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer apInterface = address.Assign (apDevice);
    Ipv4InterfaceContainer staInterfaces = address.Assign (staDevices);
    std::cout<<"Ip address set"<<std::endl;

    std::vector<DeviceProfile> profiles;
    
    profiles.push_back({"Smartphone", "HTTP", "TCP", 80, "2Mbps", 1000, 0.5, 2.0, "High"});
    profiles.push_back({"Laptop", "Download", "TCP", 8080, "50Mbps", 1460, 5.0, 1.0, "High"});
    profiles.push_back({"Camera", "Video", "UDP", 554, "4Mbps", 1400, 10.0, 0.0, "Medium"});
    profiles.push_back({"TempSensor", "MQTT", "UDP", 1883, "1Kbps", 64, 0.1, 10.0, "Low"});
    profiles.push_back({"HumidSensor", "MQTT", "UDP", 1883, "1Kbps", 64, 0.1, 10.0, "Low"});
    profiles.push_back({"Fridge", "Control", "TCP", 80, "10Kbps", 200, 0.2, 30.0, "Low"});
    profiles.push_back({"Washer", "Notify", "TCP", 80, "10Kbps", 200, 0.2, 40.0, "Low"});
    profiles.push_back({"Printer", "PrintJob", "TCP", 631, "5Mbps", 1000, 2.0, 50.0, "Medium"});
    profiles.push_back({"Switch", "CoAP", "UDP", 5683, "500bps", 32, 0.05, 5.0, "Low"});
    profiles.push_back({"SmartTV", "IPTV", "UDP", 1234, "15Mbps", 1472, 20.0, 0.1, "High"});
    profiles.push_back({"Speaker", "AudioStream", "TCP", 1935, "320Kbps", 800, 10.0, 1.0, "Medium"});
    profiles.push_back({"Mixer", "Update", "TCP", 80, "1Kbps", 100, 0.1, 55.0, "Low"});
    std::cout<<"App set"<<std::endl;

    std::ofstream labelFile;
    labelFile.open ("dataset_labels.csv");
    labelFile << "NodeID,IP,Type,TrafficCat,Protocol,CPUType,PacketSize,DataRate\n";

    
    std::set<std::pair<std::string, uint16_t>> existingSinks;

    for (const auto& prof : profiles) {
        std::pair<std::string, uint16_t> key = {prof.protocol, prof.port};

        if (existingSinks.find(key) != existingSinks.end()) {
            continue; 
        }

        existingSinks.insert(key);

        if (prof.protocol == "UDP") {
            PacketSinkHelper sink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), prof.port));
            sink.Install (apNode);
        } else {
            PacketSinkHelper sink ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), prof.port));
            sink.Install (apNode);
        }
        std::cout << "Sink installed for " << prof.protocol << " on port " << prof.port << std::endl;
    }

    // for (const auto& prof : profiles) {
    //     if (prof.protocol == "UDP") {
    //         PacketSinkHelper sink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), prof.port));
    //         sink.Install (apNode);
    //     } else {
    //         PacketSinkHelper sink ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), prof.port));
    //         sink.Install (apNode);
    //     }
    // }

    Ptr<UniformRandomVariable> startVar = CreateObject<UniformRandomVariable> ();
    startVar->SetAttribute ("Min", DoubleValue (0.0));
    startVar->SetAttribute ("Max", DoubleValue (5.0));

    Ptr<ExponentialRandomVariable> sizeVar = CreateObject<ExponentialRandomVariable> ();

    uint32_t nodeIndex = 0;
    for (uint32_t t = 0; t < nTypes; ++t) {
        DeviceProfile prof = profiles[t];
        
        for (uint32_t k = 0; k < nPerType; ++k) {
            Ptr<Node> node = staNodes.Get (nodeIndex);
            Ipv4Address nodeIp = staInterfaces.GetAddress (nodeIndex);
            
            labelFile << node->GetId() << "," << nodeIp << "," 
                      << prof.typeName << "," << prof.trafficType << "," 
                      << prof.protocol << "," << prof.cpuClass << ","
                      << prof.packetSize << "," << prof.dataRate << "\n";

            std::string socketFactory;
            if (prof.protocol == "UDP") socketFactory = "ns3::UdpSocketFactory";
            else socketFactory = "ns3::TcpSocketFactory";

            OnOffHelper onoff (socketFactory, Address (InetSocketAddress (apInterface.GetAddress (0), prof.port)));
            
            onoff.SetAttribute ("DataRate", StringValue (prof.dataRate));
            onoff.SetAttribute ("PacketSize", UintegerValue (prof.packetSize));

            std::string onTimeStr = "ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.onTimeMean) + "]";
            std::string offTimeStr = "ns3::ExponentialRandomVariable[Mean=" + std::to_string(prof.offTimeMean) + "]";
            
            onoff.SetAttribute ("OnTime", StringValue (onTimeStr));
            onoff.SetAttribute ("OffTime", StringValue (offTimeStr));

            ApplicationContainer app = onoff.Install (node);
            
            app.Start (Seconds (startVar->GetValue ()));
            app.Stop (Seconds (simTime));

            nodeIndex++;
        }
    }
    std::cout<<"Socket set"<<std::endl;
    labelFile.close();

    

	AnimationInterface anim ("traces/maison-animation.xml");


	for (uint32_t i = 0; i < staNodes.GetN (); ++i) {
    
    		anim.UpdateNodeDescription (staNodes.Get (i), "Device_" + std::to_string(i));
    		anim.UpdateNodeColor (staNodes.Get (i), 0, 0, 255); 
	}
	anim.UpdateNodeDescription (apNode.Get (0), "Access Point");
	anim.UpdateNodeColor (apNode.Get (0), 255, 0, 0); 

    wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
    
    wifiPhy.EnablePcap ("traces/maison-ap", apDevice);

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

    Simulator::Stop (Seconds (simTime));
    Simulator::Run ();

    monitor->CheckForLostPackets ();
    monitor->SerializeToXmlFile ("traces/maison-flowmon.xml", true, true);
    std::cout<<"Monitor set"<<std::endl;


    Simulator::Destroy ();
    return 0;
}
