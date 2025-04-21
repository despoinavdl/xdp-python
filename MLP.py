from torch import nn

class MLP(nn.Module):
    def __init__(self, input_dim):
        super(MLP, self).__init__()
        
        # First layer
        self.layer1 = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Dropout(0.4)
        )
        
        # Second layer
        self.layer2 = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Dropout(0.4)
        )
        
        # Third layer
        self.layer3 = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Dropout(0.3)
        )
        
        # Output layer
        self.output_layer = nn.Linear(64, 1)
        self.sigmoid = nn.Sigmoid()
        
        # Initialize with weight decay (L2 regularization)
        self.apply(self._init_weights)
    
    def _init_weights(self, m):
        if isinstance(m, nn.Linear):
            nn.init.xavier_normal_(m.weight)
            m.bias.data.fill_(0.01)
            
    def forward(self, x):
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.output_layer(x)
        x = self.sigmoid(x)
        return x