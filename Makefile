# Compilador y flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pthread
LIBS = -lpcap
TARGET = escaner_hibrido

# Directorios
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

# Archivos fuente y objetos
SRCS = main.cpp $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

# Regla principal
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Regla para compilar archivos .cpp a .o
$(BUILD_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Limpiar archivos compilados
clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: clean