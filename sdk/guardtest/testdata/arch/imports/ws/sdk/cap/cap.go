package cap

// Planted violation: sdk imports the contract module (INV-19: sdk imports
// nothing in-repo). Blank import — linkage is linkage.
import _ "example.com/pm/contract/api"
