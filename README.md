# P4-Project
https://p4.org
P4 has no loops (aside from creating a state machine loop) and no recursive functions. So looking stuff up in registers is difficult. I need to know the index of the data I want before I look at it because I can't loop through all indexes. 

This means the index has to BE the data I'm looking up, then at that index is a single bit value. I'm still trying to figure out how to define a function, to get rid of all this duplicated code.
