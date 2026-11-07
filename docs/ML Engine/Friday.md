> LEGACY PLAN — SUPERSEDED. The SMOTE instructions below are historical and must
> not be used as current implementation guidance. See `ML_ENGINE.md` and
> `VALIDITY_REVIEW.md`; the current connection split also lacks campaign independence.

The first Dataset we are going to use is the Friday Dataset to train the ML model for
the detection of intrusion.
Source: UNSW Canberra CIDS2017 Dataset

monday.csv      -- Mostly normal traffic
tuesday.csv     -- Brute force attacks
wednesday.csv   -- DoS attacks  
thursday.csv    -- Web attacks
friday.csv      -- DDoS, Port Scan, Botnet

The coloum we are going to use are following:
Column 2  -- Src Port
Column 4  -- Dst Port
Column 5  -- Protocol
Column 7  -- Flow Duration
Column 8  -- Total Fwd Packet
Column 9  -- Total Bwd Packets
Column 20 -- Flow Bytes/s
Column 21 -- Flow Packets/s
Column 22 -- Flow IAT Mean
Column 44 -- Fwd Packets/s
Column 45 -- Bwd Packets/s
Column 46 -- Packet Length Min
Column 47 -- Packet Length Max
Column 48 -- Packet Length Mean
Column 51 -- FIN Flag Count
Column 52 -- SYN Flag Count
Column 53 -- RST Flag Count
Column 54 -- PSH Flag Count
Column 55 -- ACK Flag Count
Column 60 -- Average Packet Size
Column 88 -- Label
These are the main coloum (21 out of 89) used to train the model.

BENIGN           288,544   -- Normal traffic
Portscan         159,066   -- Port scan attacks
DDoS              95,144   -- DDoS attacks
Botnet Attempted   4,067   -- Botnet attempts
Botnet               736   -- Confirmed botnet

The Problem We Need To Solve First
BENIGN     288,544   -- 52% of data
Portscan   159,066   -- 29% of data
DDoS        95,144   -- 17% of data
Botnet       4,803   -- 0.8% of data


Botnet has only 736 confirmed cases out of 547,000 rows.
This is called class imbalance. If we train on this as is, our ML model will become lazy.
It will just predict BENIGN for everything and still be 52% accurate. 
That's useless for a security system.

HOW TO FIX IT:

Two approaches combined:
Oversample minority classes  -- Create synthetic Botnet rows using SMOTE
Undersample majority class   -- Don't use all 288,544 BENIGN rows
                             -- Sample 50,000 BENIGN rows instead
After fixing this our training data looks like:
BENIGN           50,000
Portscan         50,000
DDoS             50,000
Botnet           50,000   -- SMOTE generates synthetic samples
Now our model learns all attack types equally.

Evaluation Metrics (Why accuracy is NOT enough)
If we use accuracy, the model will cheat by always predicting BENIGN (52% accuracy).
We need to measure:
1. Precision  -- Out of 100 predicted attacks, how many are real?
2. Recall     -- Out of 100 real attacks, how many did we catch?
3. F1-Score   -- Harmonic mean of precision and recall
4. Confusion Matrix -- Visual table of True Positives, False Positives, etc.

Also Simplify the Labels
Botnet and Botnet Attempted are confusing as separate classes with so few samples. Merge them:
BENIGN              -- BENIGN
Portscan            -- PORTSCAN
DDoS                -- DDOS
Botnet Attempted    -- BOTNET
Botnet              -- BOTNET
4 clean classes. Much better.

Logic for Preprocess.py
Our preprocess.py does these things in this exact order:
Step 1 -- Load friday.csv, keep only our 20 selected columns
Step 2 -- Drop the one row where Label = "Label" (header duplicate)
Step 3 -- Merge Botnet + Botnet Attempted into one label BOTNET
Step 4 -- Drop rows with infinite values
Step 5 -- Drop rows with null/missing values
Step 6 -- Sample 50,000 rows from BENIGN only
Step 7 -- Keep all Portscan and DDoS rows
Step 8 -- Keep all Botnet rows (only 4,803 total)
Step 9 -- Combine all of them into one dataframe
Step 10 -- Apply SMOTE to balance Botnet up to match others
Step 11 -- Scale all numerical features using StandardScaler
Step 12 -- Save cleaned data to dataset/processed/cleaned_data.csv

What Your Final Training Data Should Look Like
Total rows      -- roughly 200,000
Classes         -- 4 balanced classes
Columns         -- 20 features + 1 label
Nulls           -- zero
Infinite values -- zero
That is clean, balanced, ready to train data.


The algorithms we will use are:
Primary Model    -- Random Forest
Comparison Model -- XGBoost

Why we choose these Algorithms:
1. Random Forest   -- Fast, accurate, handles our data well, easy to explain
                      USE THIS as our primary model

2. XGBoost         -- Slightly better accuracy than RF but slower to train
                      USE THIS as our secondary comparison model
