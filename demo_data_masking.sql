 ---------------------------------
 --Data Masking Demo
-- Objects Created
--   DB - DEMO_DATA_MASKING
--   Schema - RAW, SECURITY
--   Role - OUTREACH_ROLE
--   Table - PATIENT_INFO, inserted 20 records
--   Masking Policies - for strings, float numerics, and rounding age
--   Conditional Masking Policies - based on CONTACT_PREFERENCE  

 
---------------------------------
-- Set variables
---------------------------------
SET db_name = 'DEMO_DATA_MASKING';
SET schema_name = 'RAW';
SET myuser_name = 'ADMIN';


---------------------------------
-- Create Database and Schema
---------------------------------
use role accountadmin;
create or replace database IDENTIFIER($db_name);
create or replace schema IDENTIFIER($schema_name);


--------------------------------------
-- Specify Database and Schema to Use
--------------------------------------
use database IDENTIFIER($db_name);
use schema IDENTIFIER($schema_name);


---------------------------------
-- Create table
---------------------------------
create or replace TABLE PATIENT_INFO (
patient_id VARCHAR,	 
patient_age integer,
marital_status VARCHAR,
total_charges float,
phone VARCHAR,
email VARCHAR,
address VARCHAR,
contact_preference varchar
    
);


---------------------------------
-- Insert sample data
---------------------------------
INSERT INTO PATIENT_INFO (patient_id, patient_age, marital_status, total_charges, phone, email, address, contact_preference)
VALUES
  ('P001', '32', 'Single', 3500, '555-0198', 'john.doe@example.com', '123 Oak St, Springfield, IL','phone'),
  ('P002', '45', 'Married', 4500, '555-0132', 'mary.smith@example.com', '456 Elm St, Springfield, IL','phone'),
  ('P003', '29', 'Single', 2500, '555-0190', 'jane.doe@example.com', '789 Pine St, Springfield, IL','phone'),
  ('P004', '60', 'Widowed', 6000, '555-0345', 'george.miller@example.com', '101 Maple St, Springfield, IL','phone'),
  ('P005', '40', 'Married', 5000, '555-0456', 'lisa.brown@example.com', '202 Birch St, Springfield, IL','phone'),
  ('P006', '38', 'Divorced', 4200, '555-0543', 'michael.white@example.com', '303 Cedar St, Springfield, IL','text'),
  ('P007', '50', 'Married', 7000, '555-0678', 'patricia.jones@example.com', '404 Oak St, Springfield, IL','text'),
  ('P008', '28', 'Single', 1800, '555-0789', 'brian.wilson@example.com', '505 Willow St, Springfield, IL','text'),
  ('P009', '35', 'Married', 3300, '555-0890', 'emily.davis@example.com', '606 Pine St, Springfield, IL','text'),
  ('P010', '56', 'Single', 5500, '555-0911', 'david.martin@example.com', '707 Elm St, Springfield, IL','text'),
  ('P011', '63', 'Widowed', 4000, '555-1022', 'nancy.taylor@example.com', '808 Maple St, Springfield, IL','email'),
  ('P012', '42', 'Married', 3800, '555-1133', 'kevin.moore@example.com', '909 Cedar St, Springfield, IL','email'),
  ('P013', '37', 'Divorced', 4200, '555-1244', 'susan.clark@example.com', '101 Pine St, Springfield, IL','email'),
  ('P014', '55', 'Single', 3300, '555-1355', 'james.lewis@example.com', '202 Birch St, Springfield, IL','email'),
  ('P015', '48', 'Married', 6000, '555-1466', 'karen.walker@example.com', '303 Oak St, Springfield, IL','email'),
  ('P016', '33', 'Single', 2700, '555-1577', 'thomas.hall@example.com', '404 Willow St, Springfield, IL','email'),
  ('P017', '60', 'Widowed', 7500, '555-1688', 'patricia.allen@example.com', '505 Maple St, Springfield, IL','home visit'),
  ('P018', '43', 'Married', 4600, '555-1799', 'joseph.king@example.com', '606 Cedar St, Springfield, IL','home visit'),
  ('P019', '30', 'Single', 2200, '555-1900', 'megan.scott@example.com', '707 Pine St, Springfield, IL','home visit'),
  ('P020', '50', 'Divorced', 4800, '555-2011', 'william.martinez@example.com', '808 Oak St, Springfield, IL','home visit');



 

-----------------------------------
-- Create outreach role 
-----------------------------------
SET role_name = 'OUTREACH_ROLE';
--Create limited, outreach coordinator role for viewing and contacting patients
--Grant our outreach coordinator the appropriate permissions
use role accountadmin;    
create or replace role IDENTIFIER($role_name);
-- my user name is admin
grant role IDENTIFIER($role_name) to user admin;




------------------------------------------------------------------------------------
-- As accountadmin and grant permissions to the outreach_role
-- Use the newly created role and observe they can view all 20 records in the table
------------------------------------------------------------------------------------
 

use role accountadmin;
grant usage on database IDENTIFIER($db_name) to role IDENTIFIER($role_name);
GRANT SELECT ON  PATIENT_INFO  to ROLE IDENTIFIER($role_name);
grant usage on schema IDENTIFIER($schema_name) to ROLE IDENTIFIER($role_name);
grant role IDENTIFIER($role_name) to user IDENTIFIER($myuser_name);

use role IDENTIFIER($role_name);
select * from PATIENT_INFO ;

 

 
 
  
------------------------------------------------
-- Create then add row access policy
-- Note the roles are all specified in UPPER CASE
------------------------------------------------
use role accountadmin;

--Create simple masking policies for strings, float numerics, and rounding age
create schema security;

create or replace masking policy security.mask_string_simple as
  (val string) returns string ->
  case
    when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
      else '**masked**'
    end;
    
create or replace masking policy security.mask_age_simple as
  (val integer) returns integer ->
  case
    when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
      else concat(substr(val, 0, 1), 0)
    end;

create or replace masking policy security.mask_float_simple as
  (val float) returns float ->
  case
    when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
      else 999.999
    end;
    
--Create conditional masking policies based on contact preference
--We will only show the contact method info for the column specified in the contact_preference column
--Only show phone number when patient specified contact via phone or text

create or replace masking policy security.phone_mask as
    (val string, contact string) returns string ->
    case
        when current_role() in ('OUTREACH_ROLE') and contact in ('phone', 'text') then val
        when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
        else 'Phone Masked'
    end;

--Only show email when patient specified contact via email
create or replace masking policy security.email_mask as 
    (val string, contact string) returns string->
    case
        when current_role() in ('OUTREACH_ROLE') and contact in ('email') then val
        when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
        else 'Email Masked'
    end;

--Only show home address when patient specified contact via home visit
create or replace masking policy security.address_mask as 
    (val string, contact string) returns string->
    case
        when current_role() in ('OUTREACH_ROLE') and contact in ('home visit') then val
        when current_role() in ('DATASCI', 'SYSADMIN', 'ACCOUNTADMIN') then val
        else 'Address Masked'
    end;




-----------------------------------------------------
--Apply masking policies to our table of predictions  
-----------------------------------------------------
use role accountadmin;
use schema  IDENTIFIER($schema_name);

alter table raw.PATIENT_INFO modify
    column patient_age set masking policy security.mask_age_simple, 
    column marital_status set masking policy security.mask_string_simple,  
    column total_charges set masking policy security.mask_float_simple,
    column phone set masking policy security.phone_mask using (phone, contact_preference),
    column email set masking policy security.email_mask using (email, contact_preference),
    column address set masking policy security.address_mask using (address, contact_preference); 



-----------------------------------------------------
--Test the policy - ACCOUNTADMIN sees everything
-----------------------------------------------------

use role accountadmin;
select * 
from patient_info;
     
---------------------------------------------------------------
--Test the policy - OUTREACH_ROLE observe masking in action:
--
--  MARITAL_STATUS = **masked** due to policy = mask_string_simple
--  TOTAL_CHARGES = 999.999 due to policy = mask_float_simple
--  AGE = increment of 10 due to policy = mask_age_simple
--  PHONE, EMAIL, ADDRESS only see the CONTACT_PREFERENCE field
--  
---------------------------------------------------------------
use role OUTREACH_ROLE;
select * 
from patient_info;
    
    
------------------------------------------------
-- Reset the environment
------------------------------------------------

use role accountadmin;
drop role IDENTIFIER($role_name);
drop database IDENTIFIER($db_name);


