**Simple Data Masking Example**
- ACCOUNTADMIN sees everything
- OUTREACH_ROLE observe masking in action:
   -  MARITAL_STATUS = **masked** due to policy = mask_string_simple
   -  TOTAL_CHARGES = 999.999 due to policy = mask_float_simple
   -  AGE = increment of 10 due to policy = mask_age_simple
   -  PHONE, EMAIL, ADDRESS only see the CONTACT_PREFERENCE field

**Objects Created**
- DB - DEMO_DATA_MASKING
-  Schema - RAW, SECURITY
-  Role - OUTREACH_ROLE
-  Table - PATIENT_INFO, inserted 20 records
-  Masking Policies - for strings, float numerics, and rounding age
-  Conditional Masking Policies - based on CONTACT_PREFERENCE 
