from ipwhois import IPWhois, IPDefinedError, ASNRegistryError, WhoisLookupError


#Modified by Samy Conejo

def whois_lookup(ip_address):
    whois = None
    err = ''
    try:
        whois = IPWhois(ip_address)
    except ValueError as e:
        err = 'Invalid IP address provided: %s.' % ip_address
    except IPDefinedError as e:
        err = '%s' % e
    except ASNRegistryError as e:
        err = '%s' % e
    except WhoisLookupError as e:
        err = 'Not Found'
    except Exception as e:
        err = 'Error: %s' % e


    if whois == None:
        return 'err'
    else:
        return whois.lookup()
