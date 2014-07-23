DANE Reverse CA Experiment
--------------------------

This is an experient to see if there is a way to drive deployment of DANE by leveraging the very PKI technology that DANE wants to replace.

DANE relies on DNS to provide a trust-bridge between DNSSEC and PKI. This service represents the reverse: by publishing DANE TLSA records you prove that you have control over the DNS domain associated with the public key. This proof is equivalent or better than normal "domain verification" performed by most commercial CAs for their baseline/free certificate service.

The DANE-validated CA takes as input a public key (in varous popular formats) and a domain-name. If there is a matching DANE record the service will sign the public key with a CA certificate. The verification process takes a few seconds and doesn't require any manual steps.

Play with it
-----------

A test-instance is running a http://dane.lab.sunet.se

Running your own
----------

You need flask & gunicorn & redis. Its very rough right now feel free to help improve it!


