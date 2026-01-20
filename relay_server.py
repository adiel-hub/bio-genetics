# relay_server.py
# A Flask relay server to proxy API requests from VAPI to BioGenetics APIs
# Run with: python relay_server.py
# Expose with: ngrok http 5000

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Simple API key for security (set this to a random string)
RELAY_API_KEY = "your-secret-relay-key-12345"

# ============================================================
# EMDEON (Insurance Eligibility) RELAY ENDPOINTS
# ============================================================

@app.route('/relay/emdeon/token', methods=['POST'])
def relay_emdeon_token():
    """Relay token request to Emdeon API"""
    # Verify API key
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    # Get credentials from request
    data = request.get_json()
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')

    # Log request
    print(f"[Emdeon Token] Getting token for client: {client_id[:8] if client_id else 'N/A'}...")

    # Forward to Emdeon
    response = requests.post(
        'https://emdeon.biologisticsolutions.com/token',
        data={
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=30
    )

    # Log response
    print(f"[Emdeon Token] Response: {response.status_code} | Token received: {str(response.text)[:50]}...")

    return jsonify(response.json()), response.status_code


@app.route('/relay/emdeon/eligibility', methods=['POST'])
def relay_emdeon_eligibility():
    """Relay eligibility check to Emdeon API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    access_token = data.get('access_token')
    patient_data = data.get('patient_data')

    # Log request
    print(f"[Emdeon Eligibility] Checking: {patient_data.get('FirstName', '')} {patient_data.get('LastName', '')} | DOB: {patient_data.get('DOB', 'N/A')} | MemberId: {patient_data.get('ParticipantId', 'N/A')}")

    response = requests.post(
        'https://emdeon.biologisticsolutions.com/v1/5867F2C5-EE0E-4DE4-9AE3-411C2DA7EE17/eligibility/check',
        json=patient_data,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        },
        timeout=30
    )

    # Log response
    print(f"[Emdeon Eligibility] Response: {response.status_code} | {response.text[:500]}")

    return jsonify(response.json()), response.status_code


# ============================================================
# CRM INTAKE RELAY ENDPOINTS
# ============================================================

@app.route('/relay/crm/token', methods=['POST'])
def relay_crm_token():
    """Relay token request to CRM API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')

    # Log request
    print(f"[CRM Token] Getting token for client: {client_id[:8] if client_id else 'N/A'}...")

    response = requests.post(
        'https://accounts.biologisticsolutions.com/v1/token',
        data={
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=30
    )

    # Log response
    print(f"[CRM Token] Response: {response.status_code} | Token received: {str(response.text)[:50]}...")

    return jsonify(response.json()), response.status_code


@app.route('/relay/crm/verify/lead/<int:lead_id>/<phone>/<agent>', methods=['GET'])
def relay_crm_verify_lead(lead_id, phone, agent):
    """Relay lead verification to CRM API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = request.headers.get('X-CRM-Token')

    # Log request
    print(f"[CRM Verify Lead] Lead ID: {lead_id} | Phone: {phone} | Agent: {agent}")

    response = requests.get(
        f'https://api.biologisticsolutions.com/v1/AI/Agent/Verify/Lead/{lead_id}/{phone}/{agent}',
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=30
    )

    # Log response
    print(f"[CRM Verify Lead] Response: {response.status_code} | {response.text[:500]}")

    return jsonify(response.json()), response.status_code


@app.route('/relay/crm/verify/member/<member_id>', methods=['GET'])
def relay_crm_verify_member(member_id):
    """Relay member ID verification to CRM API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = request.headers.get('X-CRM-Token')

    # Log request
    print(f"[CRM Verify Member] Member ID: {member_id}")

    response = requests.get(
        f'https://api.biologisticsolutions.com/v1/AI/Agent/Verify/Patient/MemberId/{member_id}',
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=30
    )

    # Log response
    print(f"[CRM Verify Member] Response: {response.status_code} | {response.text[:500]}")

    return jsonify(response.json()), response.status_code


@app.route('/relay/crm/order', methods=['POST'])
def relay_crm_order():
    """Relay patient order submission to CRM API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = request.headers.get('X-CRM-Token')
    order_data = request.get_json()

    # Log order submission
    patient_name = f"{order_data.get('firstName', '')} {order_data.get('lastName', '')}"
    print(f"[CRM Order] Submitting order for: {patient_name} | Phone: {order_data.get('homePhone', 'N/A')} | MemberId: {order_data.get('memberId', 'N/A')}")

    response = requests.post(
        'https://api.biologisticsolutions.com/v1/AI/Agent/PatientOrder',
        json=order_data,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        },
        timeout=30
    )

    # Log response
    print(f"[CRM Order] Response: {response.status_code} | {response.text[:500]}")

    try:
        return jsonify(response.json()), response.status_code
    except:
        return jsonify({"error": "Empty response", "status_code": response.status_code}), response.status_code


@app.route('/relay/crm/test-order', methods=['POST'])
def relay_crm_test_order():
    """Relay TEST patient order to CRM API (mocks data entry)

    This endpoint uses the TEST API which doesn't create real orders.
    Use for testing the order submission flow.

    Request body: Same as /relay/crm/order
    {
        "firstName": "Test",
        "lastName": "Patient",
        "dateOfBirth": "1950-03-05",
        "addressLine1": "123 Test Street",
        "city": "New York",
        "state": "NY",
        "zipCode": "10001",
        "homePhone": "3472485566",
        "gender": 1,
        "memberId": "TEST123456",
        "carrierName": "Medicare",
        "testType": "CGX",
        "insuranceType": 1
    }

    Headers: X-Relay-Key, X-CRM-Token
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = request.headers.get('X-CRM-Token')
    order_data = request.get_json()

    # Log test order submission
    patient_name = f"{order_data.get('firstName', '')} {order_data.get('lastName', '')}"
    print(f"[CRM Test Order] Submitting TEST order for: {patient_name} | Phone: {order_data.get('homePhone', 'N/A')} | MemberId: {order_data.get('memberId', 'N/A')}")

    response = requests.post(
        'https://api.biologisticsolutions.com/v1/AI/Agent/Test/PatientOrder',
        json=order_data,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        },
        timeout=30
    )

    # Log response
    print(f"[CRM Test Order] Response: {response.status_code} | {response.text[:500]}")

    try:
        return jsonify(response.json()), response.status_code
    except:
        return jsonify({"error": "Empty response", "status_code": response.status_code}), response.status_code


@app.route('/relay/crm/disposition/<int:lead_id>/<agent>', methods=['POST'])
def relay_crm_disposition(lead_id, agent):
    """Relay call disposition to CRM API"""
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    access_token = request.headers.get('X-CRM-Token')

    # Log disposition
    print(f"[CRM Disposition] Marking disposition for Lead ID: {lead_id} | Agent: {agent}")

    response = requests.post(
        f'https://api.biologisticsolutions.com/v1/AI/Agent/Mark/Call/Disposition/{lead_id}/{agent}',
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=30
    )

    # Log response
    print(f"[CRM Disposition] Response: {response.status_code} | {response.text[:500]}")

    return jsonify(response.json()), response.status_code


# ============================================================
# PVERIFY MBI LOOKUP RELAY ENDPOINTS
# ============================================================

# pVerify credentials (hardcoded for relay - client doesn't need to know these)
PVERIFY_CONFIG = {
    'token_url': 'https://api.pverify.com/Token',
    'api_base': 'https://api.pverify.com',
    'client_id': '6306f1ca-cb52-4955-a71a-933f9a0141ae',
    'client_secret': 'WUyToAn6mzwJyWdnJP7qgR1K8VYjw',
}


@app.route('/relay/pverify/token', methods=['POST'])
def relay_pverify_token():
    """Get pVerify access token using client_credentials grant

    Request body: {} (empty - credentials are stored server-side)

    Response:
    {
        "access_token": "eyJ...",
        "token_type": "bearer",
        "expires_in": 3600
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    # Log request
    print(f"[pVerify Token] Getting token...")

    response = requests.post(
        PVERIFY_CONFIG['token_url'],
        data={
            'client_id': PVERIFY_CONFIG['client_id'],
            'client_secret': PVERIFY_CONFIG['client_secret'],
            'grant_type': 'client_credentials'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=30
    )

    # Log response
    print(f"[pVerify Token] Response: {response.status_code} | Token received: {str(response.text)[:50]}...")

    return jsonify(response.json()), response.status_code


@app.route('/relay/pverify/mbi-inquiry', methods=['POST'])
def relay_pverify_mbi_inquiry():
    """Lookup Medicare Beneficiary ID (MBI) by SSN

    Request body:
    {
        "access_token": "bearer-token",
        "ProviderLastName": "Provider",
        "ProviderNPI": "1629047436",
        "PatientFirstName": "John",
        "PatientLastName": "Doe",
        "PatientDOB": "01/15/1950",
        "PatientSSN": "123456789",
        "MRN": "12345",
        "Location": ""
    }

    Response (success):
    {
        "MBI": "1ABC2DE3FG4",
        "FirstName": "JOHN",
        "LastName": "DOE",
        "DOB": "01/15/1950",
        "Message": "MBI Found",
        "APIResponseCode": "0",
        "APIResponseMessage": "Processed"
    }

    Response (NPI not approved):
    {
        "Message": "NPI is sent for CMS approval check...",
        "APIResponseCode": "4",
        "APIResponseMessage": "NPI Pending Approval"
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    access_token = data.get('access_token')

    # Log request (mask SSN)
    ssn = data.get('PatientSSN', '')
    ssn_masked = f"***{ssn[-4:]}" if len(ssn) >= 4 else '***'
    print(f"[pVerify MBI Inquiry] Patient: {data.get('PatientFirstName', '')} {data.get('PatientLastName', '')} | DOB: {data.get('PatientDOB', 'N/A')} | SSN: {ssn_masked}")

    # Build MBI inquiry payload
    mbi_payload = {
        'ProviderLastName': data.get('ProviderLastName', 'Provider'),
        'ProviderNPI': data.get('ProviderNPI'),
        'PatientFirstName': data.get('PatientFirstName'),
        'PatientLastName': data.get('PatientLastName'),
        'PatientDOB': data.get('PatientDOB'),
        'PatientSSN': data.get('PatientSSN'),
        'MRN': data.get('MRN', ''),
        'Location': data.get('Location', '')
    }

    response = requests.post(
        f"{PVERIFY_CONFIG['api_base']}/API/MBIInquiry",
        json=mbi_payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
            'Client-API-Id': PVERIFY_CONFIG['client_id']
        },
        timeout=30
    )

    # Log response
    print(f"[pVerify MBI Inquiry] Response: {response.status_code} | {response.text[:500]}")

    try:
        return jsonify(response.json()), response.status_code
    except:
        return jsonify({"error": "Invalid response", "raw": response.text[:500]}), response.status_code


@app.route('/relay/pverify/mbi-lookup', methods=['POST'])
def relay_pverify_mbi_lookup():
    """Combined endpoint: Get token + lookup MBI in one call

    Request body:
    {
        "ProviderNPI": "1629047436",
        "PatientFirstName": "John",
        "PatientLastName": "Doe",
        "PatientDOB": "01/15/1950",
        "PatientSSN": "123456789"
    }

    Response: Same as /relay/pverify/mbi-inquiry
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    # Log request (mask SSN)
    ssn = data.get('PatientSSN', '')
    ssn_masked = f"***{ssn[-4:]}" if len(ssn) >= 4 else '***'
    print(f"[pVerify MBI Lookup] Patient: {data.get('PatientFirstName', '')} {data.get('PatientLastName', '')} | DOB: {data.get('PatientDOB', 'N/A')} | SSN: {ssn_masked}")

    # Step 1: Get token
    token_response = requests.post(
        PVERIFY_CONFIG['token_url'],
        data={
            'client_id': PVERIFY_CONFIG['client_id'],
            'client_secret': PVERIFY_CONFIG['client_secret'],
            'grant_type': 'client_credentials'
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=30
    )

    if token_response.status_code != 200:
        return jsonify({"error": "Failed to get pVerify token", "details": token_response.text}), 500

    access_token = token_response.json().get('access_token')

    # Step 2: MBI Inquiry
    mbi_payload = {
        'ProviderLastName': data.get('ProviderLastName', 'Provider'),
        'ProviderNPI': data.get('ProviderNPI'),
        'PatientFirstName': data.get('PatientFirstName'),
        'PatientLastName': data.get('PatientLastName'),
        'PatientDOB': data.get('PatientDOB'),
        'PatientSSN': data.get('PatientSSN'),
        'MRN': data.get('MRN', ''),
        'Location': data.get('Location', '')
    }

    response = requests.post(
        f"{PVERIFY_CONFIG['api_base']}/API/MBIInquiry",
        json=mbi_payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
            'Client-API-Id': PVERIFY_CONFIG['client_id']
        },
        timeout=30
    )

    # Log response
    print(f"[pVerify MBI Lookup] Response: {response.status_code} | {response.text[:500]}")

    try:
        return jsonify(response.json()), response.status_code
    except:
        return jsonify({"error": "Invalid response", "raw": response.text[:500]}), response.status_code


# ============================================================
# MBI VALIDATION
# ============================================================

def validate_mbi(mbi: str) -> dict:
    """Validate Medicare Beneficiary ID (MBI) format

    MBI Format: 11 characters (dashes are for display only)
    - Position 1: Number 1-9 (not 0)
    - Position 2, 5, 8, 9: Letters A-Z (excluding S,L,O,I,B,Z)
    - Position 3, 6: Number 0-9 or Letter (excluding S,L,O,I,B,Z)
    - Position 4, 7, 10, 11: Number 0-9

    Example: 1EG4-TE5-MK73 (dashes for display only)

    Args:
        mbi: The Medicare Beneficiary ID to validate

    Returns:
        dict with 'valid' boolean, 'mbi' (cleaned), and 'errors' list if invalid
    """
    if not mbi:
        return {"valid": False, "error": "MBI is required", "errors": []}

    # Clean MBI: uppercase and remove dashes/spaces
    mbi_clean = mbi.upper().replace('-', '').replace(' ', '')

    if len(mbi_clean) != 11:
        return {
            "valid": False,
            "error": f"MBI must be exactly 11 characters, got {len(mbi_clean)}",
            "mbi": mbi_clean,
            "errors": []
        }

    # Valid characters by position type
    C = "123456789"             # Position 1 (1-9, no 0)
    N = "0123456789"            # Numbers 0-9
    A = "ACDEFGHJKMNPQRTUVWXY"  # Letters (excluding S,L,O,I,B,Z)
    AN = A + N                  # Alphanumeric

    # Position rules (1-indexed for clarity)
    position_rules = {
        1: (C, "number 1-9"),
        2: (A, "letter"),
        3: (AN, "letter or number"),
        4: (N, "number"),
        5: (A, "letter"),
        6: (AN, "letter or number"),
        7: (N, "number"),
        8: (A, "letter"),
        9: (A, "letter"),
        10: (N, "number"),
        11: (N, "number")
    }

    errors = []
    for pos, (valid_chars, expected_desc) in position_rules.items():
        char = mbi_clean[pos - 1]
        if char not in valid_chars:
            errors.append({
                "position": pos,
                "character": char,
                "expected": expected_desc
            })

    return {
        "valid": len(errors) == 0,
        "mbi": mbi_clean,
        "errors": errors
    }


@app.route('/relay/mbi/validate', methods=['POST'])
def relay_mbi_validate():
    """Validate Medicare Beneficiary ID (MBI) format in real-time

    MBI Format: 11 characters (example: 1EG4-TE5-MK73)
    - Position 1: Number 1-9 (not 0)
    - Position 2, 5, 8, 9: Letters A-Z (excluding S,L,O,I,B,Z)
    - Position 3, 6: Number 0-9 or Letter
    - Position 4, 7, 10, 11: Number 0-9

    Request body:
    {
        "mbi": "1EG4TE5MK73"  // or "1EG4-TE5-MK73" (dashes ignored)
    }

    Response (valid):
    {
        "valid": true,
        "mbi": "1EG4TE5MK73"
    }

    Response (invalid):
    {
        "valid": false,
        "mbi": "0EG4TE5MK73",
        "errors": [
            {"position": 1, "character": "0", "expected": "number 1-9"}
        ]
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    mbi = data.get('mbi', '')

    # Log request (mask middle characters for privacy)
    mbi_display = mbi[:3] + '***' + mbi[-2:] if len(mbi) >= 5 else '***'
    print(f"[MBI Validate] Validating: {mbi_display}")

    result = validate_mbi(mbi)

    # Log result
    if result['valid']:
        print(f"[MBI Validate] Valid MBI")
    else:
        print(f"[MBI Validate] Invalid MBI - Errors: {result.get('errors', [])}")

    return jsonify(result), 200


# ============================================================
# VICIDIAL RELAY ENDPOINTS
# ============================================================

# VICIdial Configuration
VICIDIAL_CONFIG = {
    'base_url': 'https://biogeneticslab.vicihost.com',
    'agent_api': '/agc/api.php',
    'non_agent_api': '/non_agent_api.php',
    'vicidial_php': '/agc/vicidial.php',
    'user': '8100',
    'pass': '810081008100',
    'agent_user': '8100',
    'phone_login': '8100',
    'phone_pass': '810081008100',
    'campaign': '',  # Set via API call
    'vapi_phone': '972539515792'
}


def vicidial_request(api_type, params):
    """Make a request to VICIdial API

    Args:
        api_type: 'agent' or 'non_agent'
        params: dict of query parameters
    """
    base_params = {
        'source': 'API',
        'user': VICIDIAL_CONFIG['user'],
        'pass': VICIDIAL_CONFIG['pass'],
        'agent_user': VICIDIAL_CONFIG['agent_user']
    }
    base_params.update(params)

    endpoint = VICIDIAL_CONFIG['agent_api'] if api_type == 'agent' else VICIDIAL_CONFIG['non_agent_api']
    url = f"{VICIDIAL_CONFIG['base_url']}{endpoint}"

    try:
        response = requests.get(url, params=base_params, timeout=30)
        return response.text, response.status_code
    except requests.exceptions.ConnectTimeout:
        return "ERROR: Connection to VICIdial timed out. The server may be temporarily unavailable.", 504
    except requests.exceptions.ConnectionError as e:
        return f"ERROR: Failed to connect to VICIdial: {str(e)}", 503
    except requests.exceptions.RequestException as e:
        return f"ERROR: VICIdial request failed: {str(e)}", 500


def parse_vicidial_response(response_text):
    """Parse VICIdial pipe-separated response"""
    if response_text.startswith('SUCCESS:'):
        return {'success': True, 'message': response_text}
    elif response_text.startswith('ERROR:'):
        # Some ERROR messages are actually informational (e.g., "agent is not paused")
        error_lower = response_text.lower()
        if 'agent is not paused' in error_lower or 'already' in error_lower:
            return {'success': True, 'message': response_text, 'info': 'Action not needed'}
        return {'success': False, 'error': response_text}
    else:
        # Parse status response (pipe-separated)
        parts = response_text.strip().split('|')
        if len(parts) >= 2:
            return {
                'success': True,
                'status': parts[0] if parts[0] else 'UNKNOWN',
                'call_id': parts[1] if len(parts) > 1 else '',
                'lead_id': parts[2] if len(parts) > 2 else '',
                'campaign_id': parts[3] if len(parts) > 3 else '',
                'raw': response_text
            }
        return {'success': True, 'raw': response_text}


@app.route('/relay/vicidial/transfer-to-agent', methods=['POST'])
def relay_vicidial_transfer_to_agent():
    """Transfer call to a live VICIdial agent using INTERNAL_TRANSFER in-group

    This endpoint is used by VAPI to transfer qualified patients back to a
    human sales agent. It uses the LOCAL_CLOSER method with the INTERNAL_TRANSFER
    in-group configured in VICIdial.

    Request body:
    {
        "destination": "sales",           // optional, for logging/routing context
        "ingroup": "INTERNAL_TRANSFER"    // optional, defaults to INTERNAL_TRANSFER
    }

    Response:
    {
        "success": true,
        "message": "SUCCESS: transfer_conference function set..."
    }

    Error Response:
    {
        "success": false,
        "error": "ERROR: agent_user does not have a live call..."
    }

    Notes:
    - Agent must be logged in and have a live call for transfer to work
    - The INTERNAL_TRANSFER in-group must be configured in VICIdial campaign
    - Uses LOCAL_CLOSER to route to available agents in the same campaign
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    destination = data.get('destination', 'sales')
    ingroup = data.get('ingroup', 'INTERNAL_TRANSFER')

    # Log request
    print(f"[VICIdial Transfer to Agent] Destination: {destination} | In-Group: {ingroup}")

    params = {
        'function': 'transfer_conference',
        'value': 'LOCAL_CLOSER',
        'ingroup_choices': ingroup
    }

    # Try transfer with 1 retry per John's email
    import time
    for attempt in range(2):
        response_text, status_code = vicidial_request('agent', params)
        result = parse_vicidial_response(response_text)

        # Success - HTTP 200 OK is the only good response per John
        if result.get('success') and status_code == 200:
            result['destination'] = destination
            result['ingroup'] = ingroup
            result['retry_attempted'] = (attempt > 0)
            print(f"[VICIdial Transfer to Agent] Success on attempt {attempt + 1}")
            return jsonify(result), 200

        # First attempt failed - retry once
        if attempt == 0:
            print(f"[VICIdial Transfer to Agent] First attempt failed, retrying in 0.5s...")
            time.sleep(0.5)
            continue

        # Second attempt also failed - return structured error for Sabrina
        print(f"[VICIdial Transfer to Agent] Transfer failed after retry")
        result['destination'] = destination
        result['ingroup'] = ingroup
        result['retry_attempted'] = True
        result['sabrina_action'] = 'TRANSFER_FAILED'
        result['sabrina_message'] = 'Transfer to agent failed. Inform patient system is down and we will call them back.'
        result['disposition_code'] = 'CALLBK'
        return jsonify(result), 500

    # Fallback (shouldn't reach here)
    return jsonify({
        'success': False,
        'error': 'Transfer failed',
        'destination': destination,
        'ingroup': ingroup,
        'retry_attempted': True,
        'sabrina_action': 'TRANSFER_FAILED',
        'sabrina_message': 'Transfer to agent failed. Inform patient system is down and we will call them back.',
        'disposition_code': 'CALLBK'
    }), 500


@app.route('/relay/vicidial/disposition', methods=['POST'])
def relay_vicidial_disposition():
    """Set call disposition

    Request body:
    {
        "status": "SALE",  // SALE, CALLBK, DNC, NQ, NQA, NI, POCALL, etc.
        "callback_datetime": "2025-01-15+12:00:00",  // optional, for CALLBK
        "callback_type": "USERONLY"  // optional, USERONLY or ANYONE
    }

    Response:
    {
        "success": true,
        "message": "SUCCESS: external_status function set..."
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    if not data.get('status'):
        return jsonify({"error": "status is required"}), 400

    # Log request
    print(f"[VICIdial Disposition] Setting status: {data['status']}")

    params = {
        'function': 'external_status',
        'value': data['status']
    }

    if data.get('callback_datetime'):
        params['callback_datetime'] = data['callback_datetime']
    if data.get('callback_type'):
        params['callback_type'] = data['callback_type']

    response_text, status_code = vicidial_request('agent', params)
    result = parse_vicidial_response(response_text)
    return jsonify(result), 200 if result.get('success') else 400


@app.route('/relay/vicidial/add-lead', methods=['POST'])
def relay_vicidial_add_lead():
    """Add lead to VICIdial - automatically triggers dialing

    When a lead is added to list 8000, VICIdial automatically initiates
    dialing to that phone number.

    Request body:
    {
        "phone_number": "13472485566",  // WITH country code!
        "first_name": "John",           // optional
        "last_name": "Doe",             // optional
        "date_of_birth": "1950-03-05",  // optional, format: YYYY-MM-DD (or MM-DD-YYYY, auto-converted)
        "gender": "M",                  // optional, M or F
        "address1": "123 Main St",      // optional
        "city": "New York",             // optional
        "state": "NY",                  // optional
        "postal_code": "10001",         // optional
        "internal_lead_id": "99999"     // optional
    }

    Response (success):
    {
        "success": true,
        "message": "SUCCESS: add_lead LEAD HAS BEEN ADDED - 10878636|8000|...",
        "lead_id": "10878636"
    }

    Response (duplicate):
    {
        "success": false,
        "error": "ERROR: add_lead DUPLICATE PHONE NUMBER IN CAMPAIGN..."
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    if not data.get('phone_number'):
        return jsonify({"error": "phone_number is required"}), 400

    # Normalize phone number - strip leading 1 if 11 digits (phone_code adds it)
    phone_number = str(data['phone_number']).strip()
    if len(phone_number) == 11 and phone_number.startswith('1'):
        phone_number = phone_number[1:]  # Remove leading 1

    phone_code = '1'  # USA country code

    # Log the separated values for debugging
    print(f"[VICIdial Add Lead] Input: {data['phone_number']} | Normalized: {phone_number} | Country Code: {phone_code}")
    print(f"[VICIdial Add Lead] Full dial number: {phone_code}{phone_number}")

    params = {
        'source': 'AIAgent',
        'user': VICIDIAL_CONFIG['user'],
        'pass': VICIDIAL_CONFIG['pass'],
        'function': 'add_lead',
        'phone_number': phone_number,
        'phone_code': phone_code,
        'list_id': '8000',
        'dnc_check': 'N',
        'duplicate_check': 'DUPCAMP',
        'custom_fields': 'Y'
    }

    # Add optional fields
    if data.get('first_name'):
        params['first_name'] = data['first_name']
    if data.get('last_name'):
        params['last_name'] = data['last_name']
    if data.get('date_of_birth'):
        # VICIdial expects YYYY-MM-DD format
        dob = str(data['date_of_birth']).strip()
        # If format is MM-DD-YYYY, convert to YYYY-MM-DD
        if len(dob) == 10 and dob[2] == '-' and dob[5] == '-':
            # MM-DD-YYYY -> YYYY-MM-DD
            parts = dob.split('-')
            if len(parts) == 3:
                dob = f"{parts[2]}-{parts[0]}-{parts[1]}"
        params['date_of_birth'] = dob
    if data.get('gender'):
        params['gender'] = data['gender']
    if data.get('address1'):
        params['address1'] = data['address1']
    if data.get('city'):
        params['city'] = data['city']
    if data.get('state'):
        params['state'] = data['state']
    if data.get('postal_code'):
        params['postal_code'] = data['postal_code']
    if data.get('internal_lead_id'):
        params['internalleadid'] = data['internal_lead_id']

    url = f"{VICIDIAL_CONFIG['base_url']}/vicidial/non_agent_api.php"

    try:
        response = requests.get(url, params=params, timeout=30)
        response_text = response.text.strip()

        # Parse the response to extract lead_id
        result = {'raw': response_text}

        if 'SUCCESS' in response_text and 'LEAD HAS BEEN ADDED' in response_text:
            result['success'] = True
            result['message'] = response_text
            # Try to extract lead_id from response like:
            # "SUCCESS: add_lead LEAD HAS BEEN ADDED - 10878636|8000|..."
            parts = response_text.split(' - ')
            if len(parts) > 1:
                lead_parts = parts[1].split('|')
                if lead_parts:
                    result['lead_id'] = lead_parts[0]
            return jsonify(result), 200
        else:
            result['success'] = False
            result['error'] = response_text
            return jsonify(result), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/relay/vicidial/update-lead', methods=['POST'])
def relay_vicidial_update_lead():
    """Update lead status in VICIdial (works without active call)

    Use this to change lead status (disposition) when there's no active call.
    This uses the Non-Agent API which doesn't require browser login.

    Request body:
    {
        "lead_id": "10904307",
        "status": "SALE"           // SALE, CALLBK, DNC, NA, XFER, etc.
    }

    Response (success):
    {
        "success": true,
        "message": "SUCCESS: update_lead LEAD HAS BEEN UPDATED - 8100|10904307|1|||",
        "lead_id": "10904307"
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    if not data.get('lead_id'):
        return jsonify({"error": "lead_id is required"}), 400

    if not data.get('status'):
        return jsonify({"error": "status is required"}), 400

    lead_id = data['lead_id']
    status = data['status']

    # Log request
    print(f"[VICIdial Update Lead] Lead ID: {lead_id} | Status: {status}")

    params = {
        'source': 'AIAgent',
        'user': VICIDIAL_CONFIG['user'],
        'pass': VICIDIAL_CONFIG['pass'],
        'function': 'update_lead',
        'lead_id': lead_id,
        'status': status
    }

    url = f"{VICIDIAL_CONFIG['base_url']}/vicidial/non_agent_api.php"

    try:
        response = requests.get(url, params=params, timeout=30)
        response_text = response.text.strip()

        if 'SUCCESS' in response_text and 'UPDATED' in response_text:
            print(f"[VICIdial Update Lead] Success: {response_text}")
            return jsonify({
                "success": True,
                "message": response_text,
                "lead_id": lead_id
            }), 200
        else:
            print(f"[VICIdial Update Lead] Failed: {response_text}")
            return jsonify({
                "success": False,
                "error": response_text,
                "lead_id": lead_id
            }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/relay/vicidial/delete-lead', methods=['POST'])
def relay_vicidial_delete_lead():
    """Delete lead from VICIdial (required before re-dialing same number)

    You can delete by lead_id directly, or by phone_number (which will
    look up the lead_id first).

    Request body (by lead_id):
    {
        "lead_id": "10878636"
    }

    OR (by phone_number - looks up lead_id first):
    {
        "phone_number": "13472485566"
    }

    Response (success):
    {
        "success": true,
        "message": "SUCCESS: update_lead LEAD HAS BEEN DELETED..."
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    lead_id = data.get('lead_id')

    # If no lead_id provided, try to look it up by phone number
    if not lead_id and data.get('phone_number'):
        # Normalize phone number - strip leading 1 if 11 digits
        phone_number = str(data['phone_number']).strip()
        if len(phone_number) == 11 and phone_number.startswith('1'):
            phone_number = phone_number[1:]  # Remove leading 1

        print(f"[VICIdial Delete Lead] Looking up phone: {phone_number}")

        # Look up lead info by phone number
        lookup_params = {
            'source': 'AIAgent',
            'user': VICIDIAL_CONFIG['user'],
            'pass': VICIDIAL_CONFIG['pass'],
            'function': 'lead_all_info',
            'phone_number': phone_number,
            'header': 'YES',
            'custom_fields': 'Y'
        }

        url = f"{VICIDIAL_CONFIG['base_url']}/vicidial/non_agent_api.php"

        try:
            response = requests.get(url, params=lookup_params, timeout=30)
            lines = response.text.strip().split('\n')

            if len(lines) >= 2:
                headers = lines[0].split('|')
                values = lines[1].split('|')

                if len(headers) == len(values):
                    lead_data = dict(zip(headers, values))
                    lead_id = lead_data.get('lead_id')

            if not lead_id:
                return jsonify({
                    "success": False,
                    "error": f"Could not find lead for phone: {phone_number}"
                }), 404

        except requests.exceptions.RequestException as e:
            return jsonify({"success": False, "error": str(e)}), 500

    if not lead_id:
        return jsonify({"error": "Either lead_id or phone_number is required"}), 400

    # Delete the lead
    params = {
        'source': 'AIAgent',
        'user': VICIDIAL_CONFIG['user'],
        'pass': VICIDIAL_CONFIG['pass'],
        'function': 'update_lead',
        'lead_id': lead_id,
        'delete_lead': 'Y'
    }

    url = f"{VICIDIAL_CONFIG['base_url']}/vicidial/non_agent_api.php"

    try:
        response = requests.get(url, params=params, timeout=30)
        response_text = response.text.strip()

        if 'SUCCESS' in response_text and 'DELETED' in response_text:
            return jsonify({
                "success": True,
                "message": response_text,
                "lead_id": lead_id
            }), 200
        else:
            return jsonify({
                "success": False,
                "error": response_text,
                "lead_id": lead_id
            }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/relay/vicidial/lead-info', methods=['POST'])
def relay_vicidial_lead_info():
    """Get lead information by phone number

    Request body:
    {
        "phone_number": "13472485566"
    }

    Response (success):
    {
        "success": true,
        "lead_id": "10878636",
        "phone_number": "13472485566",
        "first_name": "Test",
        "last_name": "User",
        "status": "NEW",
        "called_count": "0",
        "last_local_call_time": "2025-01-15 10:30:00",
        ...
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}

    if not data.get('phone_number'):
        return jsonify({"error": "phone_number is required"}), 400

    # Normalize phone number - strip leading 1 if 11 digits
    phone_number = str(data['phone_number']).strip()
    if len(phone_number) == 11 and phone_number.startswith('1'):
        phone_number = phone_number[1:]  # Remove leading 1

    print(f"[VICIdial Lead Info] Looking up phone: {phone_number}")

    params = {
        'source': 'AIAgent',
        'user': VICIDIAL_CONFIG['user'],
        'pass': VICIDIAL_CONFIG['pass'],
        'function': 'lead_all_info',
        'phone_number': phone_number,
        'header': 'YES',
        'custom_fields': 'Y'
    }

    url = f"{VICIDIAL_CONFIG['base_url']}/vicidial/non_agent_api.php"

    try:
        response = requests.get(url, params=params, timeout=30)
        lines = response.text.strip().split('\n')

        if len(lines) >= 2:
            headers = lines[0].split('|')
            values = lines[1].split('|')

            if len(headers) == len(values):
                lead_data = dict(zip(headers, values))
                lead_data['success'] = True
                return jsonify(lead_data), 200

        # Check for error
        if 'NOT FOUND' in response.text or 'ERROR' in response.text:
            return jsonify({
                "success": False,
                "error": response.text.strip()
            }), 404

        return jsonify({
            "success": False,
            "error": "Could not parse response",
            "raw": response.text
        }), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================
# GENERIC CRM API RELAY (for any endpoint)
# ============================================================

@app.route('/relay/crm/api', methods=['POST'])
def relay_crm_api():
    """Generic relay for any CRM API endpoint

    Request body:
    {
        "endpoint": "/v1/AI/Agent/...",
        "access_token": "bearer-token",
        "method": "GET" or "POST",
        "body": { ... }  // optional, for POST requests
    }
    """
    auth_header = request.headers.get('X-Relay-Key')
    if auth_header != RELAY_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    # URL-encode the endpoint path segments to handle special characters like +
    from urllib.parse import quote
    endpoint = data['endpoint']
    # Split by /, encode each segment, rejoin
    parts = endpoint.split('/')
    encoded_parts = [quote(part, safe='') if part else part for part in parts]
    encoded_endpoint = '/'.join(encoded_parts)

    url = f"https://api.biologisticsolutions.com{encoded_endpoint}"
    headers = {
        'Authorization': f"Bearer {data['access_token']}",
        'Content-Type': 'application/json'
    }

    # Log request
    print(f"[CRM API] {data.get('method', 'POST')} {data.get('endpoint', 'N/A')}")

    try:
        if data['method'] == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        else:
            response = requests.post(url, headers=headers, json=data.get('body'), timeout=30)

        # Log response
        print(f"[CRM API] Response: {response.status_code} | {response.text[:500]}")

        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "Relay server is running"})


@app.route('/', methods=['GET'])
def home():
    """Home endpoint with API info"""
    return jsonify({
        "name": "BioGenetics API Relay Server",
        "version": "1.8",
        "endpoints": {
            "health": "GET /health",
            "emdeon_token": "POST /relay/emdeon/token",
            "emdeon_eligibility": "POST /relay/emdeon/eligibility",
            "crm_token": "POST /relay/crm/token",
            "crm_verify_lead": "GET /relay/crm/verify/lead/{lead_id}/{phone}/{agent}",
            "crm_verify_member": "GET /relay/crm/verify/member/{member_id}",
            "crm_order": "POST /relay/crm/order",
            "crm_test_order": "POST /relay/crm/test-order (TEST - mocks data entry)",
            "crm_disposition": "POST /relay/crm/disposition/{lead_id}/{agent}",
            "crm_generic": "POST /relay/crm/api (endpoint, access_token, method, body in JSON)",
            "pverify_token": "POST /relay/pverify/token",
            "pverify_mbi_inquiry": "POST /relay/pverify/mbi-inquiry (with access_token)",
            "pverify_mbi_lookup": "POST /relay/pverify/mbi-lookup (combined: token + lookup)",
            "mbi_validate": "POST /relay/mbi/validate (real-time MBI format validation)",
            "vicidial_add_lead": "POST /relay/vicidial/add-lead (triggers auto-dial)",
            "vicidial_delete_lead": "POST /relay/vicidial/delete-lead (by lead_id or phone)",
            "vicidial_lead_info": "POST /relay/vicidial/lead-info (get lead by phone)",
            "vicidial_update_lead": "POST /relay/vicidial/update-lead (update lead status)",
            "vicidial_transfer_to_agent": "POST /relay/vicidial/transfer-to-agent (transfer to live agent)",
            "vicidial_disposition": "POST /relay/vicidial/disposition (set call disposition)"
        }
    })


if __name__ == '__main__':
    print("=" * 50)
    print("  BioGenetics API Relay Server v1.8")
    print("=" * 50)
    print(f"\nRelay API Key: {RELAY_API_KEY}")
    print("\nStarting server on http://0.0.0.0:5001")
    print("\nTo expose via ngrok, run in another terminal:")
    print("  ngrok http 5001")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=True)
