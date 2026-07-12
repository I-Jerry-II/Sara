# to install sara you need ollama 
# install it by writeing these commands
 
# ollama need zstd install it 
-----------------------------------
sudo apt install zstd # debain    
sudo pacman -S zstd #arch 

# install ollama 

curl -fsSL https://ollama.com/install.sh | sh  # installing ollama

# install ollama model 

ollama pull llama3.1  #installing the ollama model

ollama list  # check if llama3.1 is installed 

OLLAMA_ORIGINS=* ollama serve    # run ollama 

# you got scanner.py this one let u scan <ip> <port> in the built-in tirminal 

python3 scanner.py   # to run the scanner 


# open the html file and enjoy 
