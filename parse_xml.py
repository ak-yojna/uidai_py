from lxml import etree
from io import BytesIO
from PIL import Image
from hashlib import sha256
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
import xmlsec

# offline e-KYC
ak_xml = "./data/arun_eKYC.xml"
# suggested public key on e-KYC page of UIDAI
cer_feb_24 = "./data/uidai_offline_publickey_26022021.cer"

# ---------------------------------------
# Parse xml for required data
# ---------------------------------------
tree = etree.parse(ak_xml)
root = tree.getroot()
print(root.tag)

uid_data, uid_sig = root.getchildren()

poi, poa, pht = uid_data.getchildren()

signed_info, sig_val, key_info = uid_sig.getchildren()

signature = sig_val.text

key_details = key_info.getchildren()
keys = key_details[0].getchildren()
X509_cert = keys[1].text

# get data
# data = {}


# for name, val in poi.items():
#     data[name] = val

# for name, val in poa.items():
#     data[name] = val

# alternate way
aadhaar_data = poi.attrib
aadhaar_data.update(poa.attrib)
aadhaar_data

# photograph
encoded_pht = pht.text
decoded_pht = base64.b64decode(encoded_pht)
image = Image.open(BytesIO(decoded_pht))
image.show()
# ---------------------------------------
# validate xml file, compare digest value with hashed UidData
# ---------------------------------------


def validate_xml(xml_file):
    tree = etree.parse(xml_file)
    root = tree.getroot()

    # find the UidData element
    uiddata = root.find("UidData")
    if uiddata is None:
        raise ValueError("UidData element not found in the XML file")
    # serialize the UidData element( excluding Signature )
    # data = etree.tostring(uiddata, method="c14n2", exclusive=True, with_comments=False)
    data = etree.canonicalize(uiddata)

    # Signature Element
    sign_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    if sign_node is None:
        raise ValueError("Signature element not found in the XML file")

    # DigestValue
    dv = xmlsec.tree.find_node(sign_node, "DigestValue").text
    db_base64 = base64.b64decode(dv)
    hashed_data = sha256(data.encode()).hexdigest()

    if db_base64 == hashed_data:
        print("XML signature is valid")
    else:
        print("XML signature is not valid")

    return dv, data


# ---------------------------------------
# generate SHA
# ---------------------------------------


def generate_SHA(em, pass_code, last_digit_of_uid):
    """Generate hash for email-id and mobile number
    Parameters
    ----------
    em: str, email-id or mobile number
    pass_code: str, pass code given during download of e-KYC
    last_digit_of_uid: int

    Return
    ------
    sha256 coded email-id or mobile number
    """
    res = str(em) + str(pass_code)
    if last_digit_of_uid == 0 or last_digit_of_uid == 1:
        return sha256(res.encode()).hexdigest()
    for i in range(last_digit_of_uid):
        res = sha256(res.encode()).hexdigest()

    return res


# verify mobile number
def verify_mobile_email(mobile, email, pass_code, last_digit_of_uid):
    # check if aadhar data has mobile and email
    res_e = aadhaar_data.get("e", "not provided")
    res_m = aadhaar_data.get("m", "not provided")

    if res_e != "not provided":
        hash_e = generate_SHA(email, pass_code, last_digit_of_uid)
        if res_e == hash_e:
            print("[e] email verified")
        else:
            print("[e] email not verified")
    else:
        print("[e] email was not provided in aadhar")

    if res_m != "not provided":
        hash_m = generate_SHA(mobile, pass_code, last_digit_of_uid)
        if res_m == hash_m:
            print("[m] mobile verified")
        else:
            print("[m] mobile not verified")
    else:
        print("[m] mobile was not provided in aadhar")


# ---------------------------------------


def certificate_to_base64(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        base64_cert = base64.b64encode(cert_data).decode(
            "utf-8"
        )  # Encode to Base64 and decode to string
    return base64_cert


# Example usage
base64_cert_string = certificate_to_base64(cer_feb_24)
print(base64_cert_string)


# =================================
# xmlsec
# =================================


# sign_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignatureValue)
def verify_key(xml_file, key):
    tree = etree.parse(xml_file)
    root = tree.getroot()
    sign_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(key, xmlsec.constants.KeyDataFormatCertPem)
    ctx.key = key

    try:
        ctx.verify(sign_node)
        print("verified")
        return 0
    except Exception as e:
        print(f"[e] {e}")
        return 1


verify_key(ak_xml, cer_feb_24)
