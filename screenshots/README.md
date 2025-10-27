# Screenshots

This directory contains the required screenshots for the JWKS Server assignment submission.

## Required Screenshots

### 1. Test Client Running Against Server
- **Filename:** `test_client_screenshot.png`
- **Description:** Screenshot showing the provided test client successfully running against your JWKS server
- **Requirements:** Must include identifying information (name, date, etc.)

### 2. Test Suite Coverage Report
- **Filename:** `test_coverage_screenshot.png`
- **Description:** Screenshot showing your test suite results with coverage percentage
- **Requirements:** Must show coverage ≥80% (current: 97%)

## Instructions for Taking Screenshots

1. **Test Client Screenshot:**
   ```bash
   # Start your server
   uvicorn app.main:app --port 8080

   # Run the provided test client (download from assignment link)
   python test_client.py

   # Take screenshot showing successful tests
   ```

2. **Coverage Screenshot:**
   ```bash
   # Generate coverage report
   coverage run -m pytest
   coverage report -m

   # Take screenshot showing the coverage percentage
   ```

## Student Information
- **Student:** Jay Findoliya (11861304)
- **Date:** 09/21/2025
- **Assignment:** JWKS Server Implementation

## Notes
- Ensure all screenshots include identifying information as required
- Screenshots should clearly show the results and any terminal output
- Include your name and student ID visible in the screenshots

