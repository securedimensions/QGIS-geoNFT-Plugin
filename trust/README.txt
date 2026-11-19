Pinned CA certificates of the organisations that endorse deployment NFTs.

One file per MSP, named <mspId>.pem, with one or more CA certificates (the
organisation's msp/cacerts, which issue its peer certificates). An endorsement is
verified only when its peer certificate was issued by a CA pinned here.

  SecdMSP.pem         ca.geonft.eu
  EngineeringMSP.pem  ca.4113engineering.eu
  GeoidworksMSP.pem   ca.geoidworks.eu
