from flask import Flask,request,session,render_template,url_for,redirect,abort
from rq import Queue,get_current_job
from rq.job import Job,NoSuchJobError
from redis import Redis
from dca.tlsa import b2a_hex,getRecords,getHash,TLSARecord,RecordValidityException
from M2Crypto import X509,RSA,EVP,ASN1
import time
import random
import string
import mimetypes

app = Flask(__name__)
app.config.from_pyfile('config.py')

app.secret_key = app.config.get("SECRET")

mimetypes.add_type("application/x-x509-ca-cert",".crt")

@app.route("/")
def welcome():
   return render_template("index.html")

@app.route("/cacert")
def cacert():
   return render_template("cacert.html")

@app.route("/about")
def about():
   return render_template("about.html")

def getTLSA(hostname, port=443, protocol='tcp', secure=True):
   """
   This function tries to do a secure lookup of the TLSA record.
   At the moment it requests the TYPE52 record and parses it into a 'valid' TLSA record
   It returns a list of TLSARecord objects
   """
   if hostname[-1] != '.':
      hostname += '.'

   if not protocol.lower() in ['tcp', 'udp', 'sctp']:
      raise Exception('Error: unknown protocol: %s. Should be one of tcp, udp or sctp' % protocol)

   if port == '*':
      records = getRecords('*._%s.%s' % (protocol.lower(), hostname), rrtype=52, secure=secure)
   else:   
      records = getRecords('_%s._%s.%s' % (port, protocol.lower(), hostname), rrtype=52, secure=secure)
      ret = []
      for record in records:
         hexdata = b2a_hex(record)
         if port == '*':
            ret.append(TLSARecord('*._%s.%s' % (protocol.lower(), hostname), int(hexdata[0:2],16), int(hexdata[2:4],16), int(hexdata[4:6],16), hexdata[6:]))
         else:
            ret.append(TLSARecord('_%s._%s.%s' % (port, protocol.lower(), hostname), int(hexdata[0:2],16), int(hexdata[2:4],16), int(hexdata[4:6],16), hexdata[6:]))
   return ret

def verifyCertMatch(record, cert):
   """
   Verify the certificate with the record.
   record should be a TLSARecord and cert should be a M2Crypto.X509.X509
   """
   if not isinstance(cert, X509.X509) and not isinstance(cert, X509.Request):
      raise ValueError("first argument is not a cert or pkcs#10") 
   if not isinstance(record, TLSARecord):
      raise ValueError("second argument is not a TLSARecord")

   if record.selector == 1:
      certhash = getHash(cert.get_pubkey(), record.mtype)
   else:
      certhash = getHash(cert, record.mtype)

   if not certhash:
      return False

   return certhash == record.cert

def _load_cert(req_data):
   if 'REQUEST' in req_data:
      return X509.load_request_string(req_data)
   if 'CERTIFICATE' in req_data:
      return X509.load_cert_string(req_data)
   return None

_ca = X509.load_cert(app.config.get("ca_cert","dca/static/ca.crt"))
_pk = EVP.load_key(app.config.get("ca_key","ca.key"))

print _pk

def _mkcert(domain,req,job,days=30,hashalg="sha256"):
   cert = X509.X509()
   cert.set_serial_number(long("0x%s" % job.id.replace("-",''),0))
   cert.set_version(2)
   subject = X509.X509_Name()
   subject.CN = domain
   cert.set_subject(subject)
   cert.set_issuer(_ca.get_subject())
   cert.set_pubkey(req.get_pubkey())
   t = long(time.time())
   now = ASN1.ASN1_UTCTIME()
   now.set_time(t)
   expire = ASN1.ASN1_UTCTIME()
   expire.set_time(t + days * 24 * 60 * 60)
   cert.set_not_before(now)
   cert.set_not_after(expire)
   san = X509.new_extension('subjectAltName','DNS:%s' % domain)
   san.set_critical(0)
   cert.add_ext(san)
   cert.sign(_pk,hashalg)
   return cert.as_pem()

def do_sign(domain=None,req_data=None,port=443,protocol='tcp',secure=False):
   domain = domain.encode('ascii')
   req_data = req_data.encode('ascii')
   records = getTLSA(domain, port, protocol, secure)
   job = get_current_job()
   job.meta['success'] = False

   req = _load_cert(req_data)
    
   if req is None or not req:
      job.meta['error'] = "unable to find a useful public key container"
   else:
      for record in records:
         try:
            record.isValid(raiseException=True)
            if record.usage == 3:
               if verifyCertMatch(record,req):
                  job.meta['success'] = True
                  break
         except RecordValidityException, e:
            job.meta['error'] = str(e)

   job.save()
   return _mkcert(domain,req,job)


redis = Redis()
q = Queue(connection=redis)

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = ''.join(random.choice(string.lowercase) for i in range(50))
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route("/status")
@app.route("/status/<id>")
def status(id=None):
   if id is None:
      return redirect(url_for('welcome'))
   else:
      try:
         job = Job.fetch(id,connection=redis)
         return render_template("status.html",job=job)
      except NoSuchJobError,ex:
         abort(404)

@app.route("/contact")
def contact():
   return render_template('contact.html')

@app.route("/request",methods=['GET','POST'])
def csr():
   if request.method == 'POST':
      errors = dict()
      req_data = request.form.get('csr',None)
      if req_data is None or not req_data:
         f = request.files.get('csr',None)
         if f is not None and f:
            req_data = f.read()

      if req_data is None or not req_data:
         errors['csr_error'] = "Please provide a PEM encoded PKCS#10 certification request." 

      domain = request.form.get('domain',None)
      if domain is None or not domain:
         errors['domain_error'] = "Please provide a domain name to certify."

      if errors:
         errors.update(dict(domain=domain,csr=req_data))  
         return render_template('request.html',**errors)

      r = q.enqueue_call(do_sign,kwargs=dict(domain=domain,req_data=req_data),result_ttl=3600)
      return redirect(url_for('status',id=r.id))
   elif request.method == 'GET':
      return render_template('request.html')
   else:
      abort(405)

if __name__ == "__main__":
    app.run()
