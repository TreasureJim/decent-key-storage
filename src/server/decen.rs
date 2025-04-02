use libp2p::{futures::StreamExt, identify, noise, swarm::SwarmEvent, tcp, yamux};

pub async fn create_network(listening_addr: libp2p::Multiaddr, connect_addr: libp2p::Multiaddr, identity: libp2p_identity::Keypair) -> anyhow::Result<()> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_string(),
                key.public(),
            ))
        })?
        .build();

    swarm.listen_on(listening_addr)?;

    swarm.dial(connect_addr.clone())?;
    println!("Dialed {connect_addr}");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {address:?}"),
            // Prints peer id identify info is being sent to.
            SwarmEvent::Behaviour(identify::Event::Sent { peer_id, .. }) => {
                println!("Sent identify info to {peer_id:?}")
            }
            // Prints out the info received via the identify event
            SwarmEvent::Behaviour(identify::Event::Received { info, .. }) => {
                println!("Received {info:?}")
            }
            _ => {}
        }
    }
}
