# 🚁 AeroSleuth: Cloud-Integrated UAV Forensics Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live-FF4B4B.svg)](https://streamlit.io/)
[![Supabase](https://img.shields.io/badge/Supabase-Database-3ECF8E.svg)](https://supabase.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Live Application:** [https://aerosleuth-forensics-police-dashboard.streamlit.app/]

## 📌 Overview
As consumer drones (UAVs) become increasingly accessible, they are frequently exploited for malicious activities, including contraband delivery and targeted surveillance. Extracting raw CSV telemetry from these devices is only half the battle; law enforcement requires tools that translate chaotic spatial data into court-admissible evidence.

**AeroSleuth** is an automated digital forensics engine that bridges the gap between raw flight logs and legal evidentiary standards (such as the Bharatiya Sakshya Adhiniyam - BSA). It processes spatial telemetry to identify evasive maneuvers, maps optical footprints, and secures all findings within a Zero-Trust cryptographic cloud architecture.

## 🚀 Core Capabilities

* **Kinematic & Flight Analysis:** Automatically processes CSV telemetry using the Haversine formula to calculate true flight speeds and flags aggressive vertical drops (indicative of contraband delivery).
* **3D Geospatial Mapping:** Renders interactive, 3D visualizations of the drone's flight path using `Pydeck`, allowing investigators to trace the exact route over a map.
* **Optical Footprint Projection:** Utilizes spatial trigonometry (Pitch, Roll, Yaw, and Altitude) to calculate the camera's ground target, proving intent (*Mens Rea*) in illegal surveillance cases.
* **Zero-Trust Chain of Custody:** Integrates with Supabase (PostgreSQL) using strict Row Level Security (RLS). All uploaded evidence and investigator actions are stored in an immutable, append-only audit log to prevent spoliation.

## 🛠️ System Architecture & Tech Stack

* **Frontend:** Streamlit (Python)
* **Data Processing:** Pandas, NumPy
* **Spatial Visualization:** Pydeck (Deck.gl)
* **Backend Vault:** Supabase (Cloud Storage & PostgreSQL)
* **Security:** Role-Based Access Control (RBAC), Immutable Audit Logging
