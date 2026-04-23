#!/usr/bin/env python3
"""
Complete Model Training Pipeline for Threat Detection System
"""

import os
import sys
import subprocess
from datetime import datetime

def run_training_pipeline():
    """Run the complete model training pipeline"""
    print("🚀 Starting Complete Model Training Pipeline")
    print("=" * 60)
    
    # Create Ai_Model directory
    os.makedirs('Ai_Model', exist_ok=True)
    
    steps = [
        ("Training Base Models", "train_enhanced_model.py"),
        ("Creating Ensemble", "create_ensemble.py"), 
        ("Model Evaluation", "evaluation.py")
    ]
    
    for step_name, script_name in steps:
        print(f"\n📍 Step: {step_name}")
        print("-" * 40)
        
        try:
            result = subprocess.run([sys.executable, script_name], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Success!")
                print(result.stdout)
            else:
                print("❌ Failed!")
                print(result.stderr)
                return False
                
        except Exception as e:
            print(f"❌ Error running {script_name}: {e}")
            return False
    
    print(f"\n🎉 Pipeline completed successfully!")
    print(f"🤖 Your AI models are ready in: Ai_Model/")
    
    # List created files
    print(f"\n📁 Generated Model Files:")
    model_files = os.listdir('Ai_Model')
    for file in sorted(model_files):
        size = os.path.getsize(os.path.join('Ai_Model', file))
        print(f"   📄 {file} ({size / 1024:.1f} KB)")
    
    return True

if __name__ == "__main__":
    success = run_training_pipeline()
    
    if success:
        print(f"\n🎊 All done! Your Threat Detection System is ready!")
        print(f"🔧 Next steps:")
        print(f"   1. Run: python app.py")
        print(f"   2. Open: http://localhost:5000")
        print(f"   3. Upload log files for analysis!")
    else:
        print(f"\n💥 Pipeline failed. Please check the errors above.")
        sys.exit(1)