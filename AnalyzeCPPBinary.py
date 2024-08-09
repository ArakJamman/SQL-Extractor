import re
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import DataType

# Step 1: Find embedded SQL queries in the binary
def find_sql_queries():
    strings = currentProgram.getListing().getDefinedStrings(True)
    sql_queries = []
    
    sql_pattern = re.compile(r"SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|JOIN", re.IGNORECASE)
    
    for s in strings:
        string_value = str(s)
        if sql_pattern.search(string_value):
            sql_queries.append((s.getAddress(), string_value))
            print(f"Found SQL query at {s.getAddress()}: {string_value}")
    
    return sql_queries

# Step 2: Analyze database-related function calls
def analyze_db_function_calls():
    function_manager = currentProgram.getFunctionManager()
    db_functions = []
    db_keywords = ["PQexec", "PQconnectdb", "sqlite3_exec", "mysql_query"]  # Common DB functions
    
    for function in function_manager.getFunctions(True):
        if any(keyword in function.getName() for keyword in db_keywords):
            db_functions.append(function)
            print(f"Found database-related function: {function.getName()}")
    
    return db_functions

# Step 3: Infer data types from function parameters
def infer_data_types_from_functions(functions):
    table_schemas = {}
    
    for function in functions:
        print(f"\nAnalyzing function: {function.getName()}")
        
        parameters = function.getParameters()
        for param in parameters:
            param_name = param.getName()
            param_type = param.getDataType().getName()
            print(f"Parameter {param_name}: Type {param_type}")
            
            table_name = function.getName().replace("PQexec_", "").replace("_Query", "")
            if table_name not in table_schemas:
                table_schemas[table_name] = {}
            
            table_schemas[table_name][param_name] = param_type
    
    return table_schemas

# Step 4: Analyze JOIN statements to determine table relationships
def analyze_join_statements(sql_queries):
    join_pattern = re.compile(r"JOIN\s+(\w+)\s+ON\s+(\w+\.\w+)\s*=\s*(\w+\.\w+)", re.IGNORECASE)
    relationships = []

    for addr, query in sql_queries:
        match = join_pattern.search(query)
        if match:
            left_table = match.group(1)
            left_column = match.group(2)
            right_table = match.group(3)
            right_column = match.group(4)
            relationships.append((left_table, left_column, right_table, right_column))
            print(f"JOIN found: {left_table}.{left_column} = {right_table}.{right_column}")
    
    return relationships

# Step 5: Analyze memory layout and data structures
def analyze_memory_structures():
    listing = currentProgram.getListing()
    data = listing.getDefinedData(True)
    struct_types = {}
    
    for d in data:
        data_type = d.getDataType()
        if isinstance(data_type, DataType):
            struct_name = data_type.getName()
            if struct_name not in struct_types:
                struct_types[struct_name] = []
            struct_types[struct_name].append(d.getAddress())
            print(f"Data structure found: {struct_name} at {d.getAddress()}")
    
    return struct_types

# Step 6: Generate CREATE TABLE statements
def generate_create_table_statements(table_schemas, table_relationships):
    for table_name, columns in table_schemas.items():
        create_statement = f"CREATE TABLE {table_name} (\n"
        create_statement += ",\n".join([f"    {col} {dtype}" for col, dtype in columns.items()])
        
        for rel in table_relationships:
            if table_name == rel[0]:
                create_statement += f",\n    FOREIGN KEY ({rel[1]}) REFERENCES {rel[2]}({rel[3]})"
            elif table_name == rel[2]:
                create_statement += f",\n    FOREIGN KEY ({rel[3]}) REFERENCES {rel[0]}({rel[1]})"
        
        create_statement += "\n);"
        print(create_statement)

# Run the combined analysis
sql_queries = find_sql_queries()
db_functions = analyze_db_function_calls()
table_schemas = infer_data_types_from_functions(db_functions)
table_relationships = analyze_join_statements(sql_queries)
memory_structures = analyze_memory_structures()
generate_create_table_statements(table_schemas, table_relationships)
