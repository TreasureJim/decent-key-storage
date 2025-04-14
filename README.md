# TODO

## Decentralised Certificate Node (DCN)

- [ ] Test connection between server and client
- [ ] Create swarm for decentralised network
- [ ] Create API for responding with public key
- [x] System for storing keys
- [ ] API for enabling advertising on mDNS
- [ ] Message propagation

# Server

## Authenticating admins

- Checking that they can authenticate an OS user within a certain group

## Adding user

New user code
- Admin goes to 2 or more servers and initiates adding user protocol
- The servers contact each other and establish a secret
    - secret = hash(random + timestamp)
    - Servers sign the secret and send the signed message to each other
    - Code contains IP addresses of the servers and hash(secret + timestamp)
- Admin enters 

## New User Propagation

ClientJoinRequest: {
    joining key
    public key
    verification key
}

ServerSignClientJoinRequest {
    IP
    verification key
}

ServerClientAdd: {
    ClientJoinRequest
    repeated ServerSignClientJoinRequest
}

# Concerns

What stops a rogue server from adding its own child servers?
Answer: each message will sign the secret they agree on and the propogation will contain this signed message. The propogated message needs to contain signed version from all the initial nodes
