import streamlit as st
import pandas as pd
import pydeck as pdk
import math
import hashlib
import time
from supabase import create_client, Client

# --- 1. SUPABASE CONNECTION ---
SUPABASE_URL = "https://dddzbdhdflcyjjsnggod.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRkZHpiZGhkZmxjeWpqc25nZ29kIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM5MjgyMTEsImV4cCI6MjA4OTUwNDIxMX0.yQV3IFrNUKDE8VKsOzshuiowPtWLpTPgIZnkh8sGr-U"

@st.cache_resource
def init_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    supabase: Client = init_supabase()
except Exception as e:
    st.error("Failed to connect to Supabase. Check your URL and Key.")

# --- 2. SESSION STATE MEMORY & AUTO-RESUME ---
if 'logged_in' not in st.session_state:
    saved_user = st.query_params.get("logged_in_user")
    if saved_user:
        try:
            response = supabase.table("users").select("*").eq("username", saved_user).execute()
            if len(response.data) > 0:
                user_record = response.data[0]
                st.session_state.logged_in = True
                st.session_state.username = user_record["username"]
                st.session_state.role = user_record["role"]
            else:
                st.session_state.logged_in = False
                st.session_state.username = ""
                st.session_state.role = ""
        except Exception:
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.role = ""
    else:
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.role = ""

if 'evidence_loaded' not in st.session_state:
    st.session_state.evidence_loaded = False
    st.session_state.raw_data = None
    st.session_state.parsed_data = None
    st.session_state.filename = ""
    st.session_state.anomalies = []
if 'full_report_text' not in st.session_state:
    st.session_state.full_report_text = ""

# --- 3. SECURITY & AUDIT LOGGING ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def log_activity(username, action, target_file="N/A"):
    try:
        supabase.table("audit_logs").insert({"username": username, "action": action, "target_file": target_file}).execute()
    except Exception as e:
        pass 

# --- 4. FORENSIC ENGINES (WITH NEW KINEMATIC TOOLS) ---
def normalize_telemetry(df):
    column_map = {'OSD.latitude': 'Latitude', 'Lat': 'Latitude', 'gps_lat': 'Latitude', 'OSD.longitude': 'Longitude', 'Lng': 'Longitude', 'gps_lon': 'Longitude', 'OSD.altitude [m]': 'Altitude', 'Altitude(meters)': 'Altitude', 'alt': 'Altitude', 'OSD.pitch': 'Pitch', 'pitch': 'Pitch', 'gimbal_pitch': 'Pitch', 'OSD.yaw': 'Yaw', 'yaw': 'Yaw', 'compass_heading': 'Yaw', 'OSD.flyTime [s]': 'Time', 'Time(seconds)': 'Time', 'flight_time': 'Time'}
    return df.rename(columns=lambda x: column_map.get(x, x))

def calculate_target_gps(lat, lon, altitude, pitch, yaw):
    pitch = max(1, min(abs(pitch), 89))
    angle_rad = math.radians(90 - pitch)
    distance_to_target = altitude * math.tan(angle_rad)
    R = 6378137.0 
    lat_rad, lon_rad, yaw_rad = math.radians(lat), math.radians(lon), math.radians(yaw)
    target_lat = math.asin(math.sin(lat_rad) * math.cos(distance_to_target / R) + math.cos(lat_rad) * math.sin(distance_to_target / R) * math.cos(yaw_rad))
    target_lon = lon_rad + math.atan2(math.sin(yaw_rad) * math.sin(distance_to_target / R) * math.cos(lat_rad), math.cos(distance_to_target / R) - math.sin(lat_rad) * math.sin(target_lat))
    return math.degrees(target_lat), math.degrees(target_lon), distance_to_target

# NEW: Math to calculate distance between two GPS points
def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371000 # Earth radius in meters
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi, dlambda = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))

def scan_for_crimes(df):
    alerts = []
    if 'Altitude' in df.columns and df['Altitude'].max() > 120: 
        alerts.append(f"🚨 ILLEGAL FLIGHT HEIGHT: Drone flew {df['Altitude'].max():.1f} meters high.")
    if 'Time' in df.columns and (df['Time'].diff().dropna() > 5).any(): 
        alerts.append("🚨 DATA DELETED: Missing chunks of time. Possible tampering.")
    
    if all(col in df.columns for col in ['Pitch', 'Latitude', 'Longitude', 'Altitude', 'Yaw']):
        suspicious_angles = df[df['Pitch'].abs() >= 30]
        if len(suspicious_angles) >= 5: 
            crime_frame = suspicious_angles.iloc[len(suspicious_angles)//2]
            t_lat, t_lon, dist = calculate_target_gps(crime_frame['Latitude'], crime_frame['Longitude'], crime_frame['Altitude'], crime_frame['Pitch'], crime_frame['Yaw'])
            alerts.append(f"🚨 TARGETED SURVEILLANCE DETECTED: Camera pointed sharply down at a fixed target.\n📍 EXACT TARGET COORDINATES: {t_lat:.6f}, {t_lon:.6f} (Distance: {dist:.1f}m)")
            
    # NEW TOOL ALERT: Speed Check
    if 'Speed_kmh' in df.columns and df['Speed_kmh'].max() > 50:
        alerts.append(f"🚨 EVASIVE MANEUVERS / FLEEING: Drone reached high speeds of {df['Speed_kmh'].max():.1f} km/h.")
        
    return alerts

# --- UI CONFIGURATION ---
st.set_page_config(page_title="AeroSleuth | Police Dashboard", page_icon="🚁", layout="wide")

# --- 5. LOGIN & REGISTRATION SYSTEM ---
def auth_screen():
    st.markdown("<h1 style='text-align: center; color: #FF4B4B;'>🚁 AeroSleuth Secure Terminal</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Authorized Law Enforcement Personnel Only</p>", unsafe_allow_html=True)
    st.divider()
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        tab1, tab2 = st.tabs(["🔒 Login", "📝 Request Account"])
        with tab1:
            login_user = st.text_input("Username", key="log_user")
            login_pass = st.text_input("Password", type="password", key="log_pass")
            if st.button("Secure Login", use_container_width=True):
                response = supabase.table("users").select("*").eq("username", login_user).execute()
                if len(response.data) > 0:
                    user_record = response.data[0]
                    if hash_password(login_pass) == user_record["password"] or login_pass == user_record["password"]:
                        if user_record["is_approved"]:
                            log_activity(user_record["username"], "System Login")
                            st.session_state.logged_in = True
                            st.session_state.username = user_record["username"]
                            st.session_state.role = user_record["role"]
                            st.query_params["logged_in_user"] = user_record["username"]
                            st.rerun()
                        else: st.error("🚨 ACCOUNT PENDING: Your account is waiting for Admin approval.")
                    else: st.error("❌ Incorrect Password.")
                else: st.error("❌ User not found.")
        with tab2:
            reg_user = st.text_input("Choose a Username", key="reg_user")
            reg_pass = st.text_input("Choose a Password", type="password", key="reg_pass")
            if st.button("Submit Registration Request", use_container_width=True):
                if len(reg_user) < 3 or len(reg_pass) < 3:
                    st.warning("Username and password must be at least 3 characters.")
                else:
                    check = supabase.table("users").select("*").eq("username", reg_user).execute()
                    if len(check.data) > 0: st.error("Username already taken.")
                    else:
                        new_user = {"username": reg_user, "password": hash_password(reg_pass), "role": "Investigator", "is_approved": False}
                        supabase.table("users").insert(new_user).execute()
                        st.success("✅ Request Submitted! Please wait for an Admin to approve your account.")

# --- 6. ADMIN DASHBOARD ---
def admin_dashboard():
    st.header("👑 Administrator Control Panel")
    with st.sidebar:
        st.success(f"👤 Logged in as: **{st.session_state.username}** (Admin)")
        if st.button("🚪 Secure Logout"):
            log_activity(st.session_state.username, "System Logout")
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.query_params.clear()
            st.rerun()

    tab1, tab2, tab3 = st.tabs(["🟢 Pending Approvals", "🕵️ Live Activity Monitor", "🗄️ Global Evidence Vault"])
    with tab1:
        st.subheader("User Authorization Queue")
        response = supabase.table("users").select("*").eq("is_approved", False).execute()
        if len(response.data) == 0: st.info("No pending approvals at this time.")
        else:
            for user in response.data:
                colA, colB = st.columns([3, 1])
                colA.write(f"👤 **{user['username']}** (Role: {user['role']})")
                if colB.button(f"Approve {user['username']}", key=f"app_{user['username']}"):
                    supabase.table("users").update({"is_approved": True}).eq("username", user['username']).execute()
                    log_activity("Admin", "Approved New User", user['username'])
                    st.success(f"Approved {user['username']}!")
                    time.sleep(1)
                    st.rerun()
    with tab2:
        st.subheader("Live Anti-Espionage Audit Trail")
        if st.button("🔄 Refresh Logs"): st.rerun()
        try:
            logs_response = supabase.table("audit_logs").select("*").order("created_at", desc=True).limit(50).execute()
            if len(logs_response.data) > 0:
                df_logs = pd.DataFrame(logs_response.data)[['created_at', 'username', 'action', 'target_file']]
                df_logs.rename(columns={'created_at': 'Timestamp', 'username': 'User', 'action': 'Action Taken', 'target_file': 'Evidence File'}, inplace=True)
                df_logs['Timestamp'] = pd.to_datetime(df_logs['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                st.dataframe(df_logs, use_container_width=True, hide_index=True)
            else: st.info("No activity logged yet.")
        except: st.warning("Could not fetch audit logs.")
    
    with tab3:
        st.subheader("Global Evidence Directory")
        st.write("View every CSV and Court Report uploaded across all accounts.")
        if st.button("🔄 Refresh Global Vault"): st.rerun()
        try:
            files_response = supabase.storage.from_("evidence-locker").list()
            valid_files = [f for f in files_response if f['name'] != '.emptyFolderPlaceholder']
            
            if len(valid_files) > 0:
                global_data = []
                file_names = []
                for f in valid_files:
                    parts = f['name'].split('_', 2)
                    uploader = parts[0] if len(parts) >= 3 else "Unknown"
                    clean_name = parts[2] if len(parts) >= 3 else f['name']
                    file_type = "📄 Report" if clean_name.startswith("Report_") else "📊 CSV Data"
                    
                    global_data.append({
                        "Uploader": uploader, 
                        "Date": f['created_at'][:10], 
                        "Type": file_type, 
                        "File Name": clean_name.replace("Report_", "")
                    })
                    file_names.append(f['name'])
                    
                st.dataframe(pd.DataFrame(global_data), use_container_width=True, hide_index=True)
                
                st.divider()
                st.subheader("📥 Secure File Extraction Panel")
                st.info("Downloading files from the Global Vault will permanently record your action in the Audit Trail.")
                selected_download = st.selectbox("Select Evidence to Extract:", file_names)
                
                if selected_download:
                    try:
                        file_bytes = supabase.storage.from_("evidence-locker").download(selected_download)
                        st.download_button(
                            label=f"Extract & Download Data",
                            data=file_bytes,
                            file_name=selected_download,
                            on_click=log_activity,
                            args=(st.session_state.username, "Admin Extracted Evidence from Global Vault", selected_download)
                        )
                    except Exception as e:
                        st.error(f"Could not prepare file for download: {str(e)}")
                        
            else: st.info("The global vault is currently empty.")
        except Exception as e: st.warning(f"Could not fetch global vault. Error: {str(e)}")

# --- 7. INVESTIGATOR DASHBOARD ---
def investigator_dashboard():
    st.markdown("<h1 style='text-align: center; color: #FF4B4B;'>🚁 AeroSleuth Forensic Command Center</h1>", unsafe_allow_html=True)
    st.divider()

    with st.sidebar:
        st.success(f"👤 Logged in as: **{st.session_state.username}**")
        if st.button("🚪 Secure Logout"):
            log_activity(st.session_state.username, "System Logout")
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.evidence_loaded = False
            st.query_params.clear()
            st.rerun()
            
        st.header("📁 Evidence Locker")
        uploaded_file = st.file_uploader("Upload Drone File (.csv)", type=['csv'])

    tab_main, tab_vault = st.tabs(["🚁 Active Case Analysis", "🗄️ My Cloud Evidence Vault"])

    with tab_main:
        if uploaded_file is not None and not st.session_state.evidence_loaded:
            try:
                df_raw = pd.read_csv(uploaded_file, low_memory=False)
                df_parsed = normalize_telemetry(df_raw)
                
                # --- NEW TOOL: CALCULATE DRONE SPEED DYNAMICALLY ---
                speeds = [0]
                if all(col in df_parsed.columns for col in ['Latitude', 'Longitude', 'Time']):
                    for i in range(1, len(df_parsed)):
                        dist = haversine_distance(df_parsed.iloc[i-1]['Latitude'], df_parsed.iloc[i-1]['Longitude'], df_parsed.iloc[i]['Latitude'], df_parsed.iloc[i]['Longitude'])
                        time_diff = df_parsed.iloc[i]['Time'] - df_parsed.iloc[i-1]['Time']
                        speed_mps = dist / time_diff if time_diff > 0 else 0
                        speeds.append(speed_mps * 3.6) # Convert m/s to km/h
                df_parsed['Speed_kmh'] = speeds
                
                # Scan for anomalies (now including speed)
                anomalies = scan_for_crimes(df_parsed)
                
                distances = []
                if all(col in df_parsed.columns for col in ['Latitude', 'Longitude', 'Altitude', 'Pitch', 'Yaw']):
                    for index, row in df_parsed.iterrows():
                        _, _, dist = calculate_target_gps(row['Latitude'], row['Longitude'], row['Altitude'], row['Pitch'], row['Yaw'])
                        distances.append(dist)
                
                file_hash = hashlib.sha256(df_raw.to_csv().encode()).hexdigest()
                crime_summary = "\n\n".join(anomalies) if anomalies else "No tampering or illegal maneuvers detected."
                duration = int(df_parsed['Time'].max()) if 'Time' in df_parsed.columns else "Unknown"
                max_alt = round(df_parsed['Altitude'].max(), 1) if 'Altitude' in df_parsed.columns else "Unknown"
                max_speed = round(df_parsed['Speed_kmh'].max(), 1) if 'Speed_kmh' in df_parsed.columns else "Unknown"
                max_dist = round(max(distances), 1) if distances else 'Unknown'

                full_report = f"""=========================================================
          AEROSLEUTH COMPREHENSIVE COURT REPORT
=========================================================
Investigating Officer: {st.session_state.username}
Date of Extraction: {time.strftime("%Y-%m-%d %H:%M:%S")}
Original File Name: {uploaded_file.name}
Digital Fingerprint (SHA-256): {file_hash}

---------------------------------------------------------
SECTION 1: KINEMATIC & FLIGHT SUMMARY
---------------------------------------------------------
Total Flight Time: {duration} seconds.
Maximum Altitude: {max_alt} meters.
Maximum Speed Reached: {max_speed} km/h.

---------------------------------------------------------
SECTION 2: AUTOMATED CRIME & TARGETING AUDIT
---------------------------------------------------------
FINDINGS:
{crime_summary}
========================================================="""
                
                st.session_state.raw_data = df_raw
                st.session_state.parsed_data = df_parsed
                st.session_state.filename = uploaded_file.name
                st.session_state.anomalies = anomalies
                st.session_state.full_report_text = full_report
                st.session_state.evidence_loaded = True
                
                try:
                    timestamp = int(time.time())
                    safe_csv_name = f"{st.session_state.username}_{timestamp}_{uploaded_file.name}"
                    safe_txt_name = f"{st.session_state.username}_{timestamp}_Report_{uploaded_file.name}.txt"
                    
                    supabase.storage.from_("evidence-locker").upload(safe_csv_name, uploaded_file.getvalue())
                    supabase.storage.from_("evidence-locker").upload(safe_txt_name, full_report.encode('utf-8'))
                    log_activity(st.session_state.username, "Archived Evidence to Cloud", safe_csv_name)
                    st.sidebar.success("✅ Saved to Cloud Vault!")
                except Exception as vault_error:
                    st.sidebar.error(f"⚠️ Cloud Upload Failed: {str(vault_error)}")
                
                st.rerun() 
            except Exception as e:
                st.error(f"**🚨 ERROR PROCESSING FILE:** {str(e)}")

        if st.session_state.evidence_loaded:
            if st.button("🗑️ Clear Active Screen"):
                st.session_state.evidence_loaded = False
                st.session_state.raw_data = None
                st.rerun()
                
            df = st.session_state.parsed_data
            if len(st.session_state.anomalies) > 0:
                st.error(f"### 🛑 INVESTIGATION ALERT: {len(st.session_state.anomalies)} CRIMES DETECTED")
                for alert in st.session_state.anomalies: st.markdown(f"**{alert}**")
            else: st.success("### ✅ No tampering or illegal maneuvers detected.")

            # --- THE NEW FORENSIC MULTI-TOOL SUITE UI ---
            tool1, tool2, tool3, tool4 = st.tabs(["🗺️ 3D Crime Map", "📍 Pilot Origin Locator", "🏃‍♂️ Speed Analyzer", "📄 Court Report"])
            
            with tool1:
                st.subheader("3D Spatial Flight & Surveillance Map")
                try:
                    target_lats, target_lons = [], []
                    for index, row in df.iterrows():
                        t_lat, t_lon, _ = calculate_target_gps(row['Latitude'], row['Longitude'], row['Altitude'], row['Pitch'], row['Yaw'])
                        target_lats.append(t_lat)
                        target_lons.append(t_lon)
                    df['Target_Lat'], df['Target_Lon'] = target_lats, target_lons
                    
                    # 3D Column mapping for elevation
                    drone_layer = pdk.Layer("ColumnLayer", data=df, get_position=['Longitude', 'Latitude'], get_elevation='Altitude', elevation_scale=1, radius=2, get_fill_color="[0, 100, 255, 255]", pickable=True, auto_highlight=True)
                    target_layer = pdk.Layer("ScatterplotLayer", data=df, get_position=["Target_Lon", "Target_Lat"], get_color="[255, 0, 0, 200]", get_radius=5)
                    view_state = pdk.ViewState(latitude=df['Latitude'].mean(), longitude=df['Longitude'].mean(), zoom=17, pitch=60, bearing=0)
                    st.pydeck_chart(pdk.Deck(layers=[drone_layer, target_layer], initial_view_state=view_state, tooltip={"text": "Altitude: {Altitude}m"}))
                except Exception: st.warning("Could not draw the map. Missing GPS/Camera data.")

            with tool2:
                st.subheader("📍 Pilot Origin Locator")
                st.write("Extracts the very first GPS coordinate from the flight log to pinpoint where the suspect likely launched the drone.")
                try:
                    home_lat = df['Latitude'].iloc[0]
                    home_lon = df['Longitude'].iloc[0]
                    st.metric("Suspect Launch Coordinates", f"{home_lat:.6f}, {home_lon:.6f}")
                    
                    home_df = pd.DataFrame({'lat': [home_lat], 'lon': [home_lon]})
                    st.map(home_df, zoom=18, color="#00ff00")
                except: st.warning("No valid GPS data to locate pilot origin.")

            with tool3:
                st.subheader("🏃‍♂️ Kinematics & Evasive Maneuvers Analyzer")
                st.write("Tracks drone speed over time to detect fleeing or reckless flying.")
                try:
                    st.line_chart(df[['Time', 'Speed_kmh']].set_index('Time'), color="#ff4b4b")
                    st.metric("Max Speed Detected", f"{df['Speed_kmh'].max():.1f} km/h")
                except: st.warning("Could not calculate speed without valid Time/GPS data.")

            with tool4:
                st.text_area("Preview of Court Report", st.session_state.full_report_text, height=300)
                st.download_button("📥 Download Copy to Computer", st.session_state.full_report_text, f"Report_{st.session_state.filename}.txt", "text/plain")
        else:
            st.info("👈 Please upload an evidence file in the sidebar to begin analysis.")

    with tab_vault:
        st.subheader("🗄️ Your Secure Evidence Vault")
        st.write("These are the past cases securely linked to your law enforcement ID. They are permanently stored in the cloud.")
        if st.button("🔄 Refresh My Vault"): st.rerun()
        try:
            files_response = supabase.storage.from_("evidence-locker").list()
            user_prefix = f"{st.session_state.username}_"
            my_files = [f for f in files_response if f['name'].startswith(user_prefix)]
            
            if len(my_files) > 0:
                history_data = []
                file_names = []
                for f in my_files:
                    parts = f['name'].split('_', 2)
                    clean_name = parts[2] if len(parts) == 3 else f['name']
                    file_type = "📄 Report" if clean_name.startswith("Report_") else "📊 CSV Data"
                    history_data.append({"Date": f['created_at'][:10], "Type": file_type, "File Name": clean_name.replace("Report_", "")})
                    file_names.append(f['name'])
                    
                st.dataframe(pd.DataFrame(history_data), use_container_width=True, hide_index=True)
                
                st.divider()
                st.subheader("📥 Secure File Extraction Panel")
                selected_vault_file = st.selectbox("Select file to download:", file_names)
                if selected_vault_file:
                    try:
                        file_bytes = supabase.storage.from_("evidence-locker").download(selected_vault_file)
                        st.download_button(
                            label=f"Extract & Download Data",
                            data=file_bytes,
                            file_name=selected_vault_file,
                            on_click=log_activity,
                            args=(st.session_state.username, "Extracted Own Evidence from Personal Vault", selected_vault_file)
                        )
                    except Exception as e:
                        st.error("Could not fetch file for download.")
                        
            else: st.write("Your vault is empty. Upload a file to save it permanently.")
        except Exception as e:
            st.warning(f"⚠️ Cannot fetch vault history. Error: {str(e)}")

# --- 8. APP ROUTING LOGIC ---
if not st.session_state.logged_in: auth_screen()
else:
    if st.session_state.role == "Admin": admin_dashboard()
    else: investigator_dashboard()