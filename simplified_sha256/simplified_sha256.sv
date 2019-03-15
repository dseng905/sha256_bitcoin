// Simplified SHA 256 Module (ECE 111)
// By Sovanarung (Davin) Seng and Fengze (Adrian) Yu
// NOTE: This SHA 256 module will only work for 20 word messages.
// TODO: Write function to pad message of any size.
// TODO: Write function or algorithm to message to n blocks.
// TODO: Reduce number of cycles by using less states.


module simplified_sha256(input logic clk, reset_n, start,
            input logic [15:0] message_addr, output_addr,
           output logic done, mem_clk, mem_we,
           output logic [15:0] mem_addr,
           output logic [31:0] mem_write_data,
            input logic [31:0] mem_read_data);

parameter int k[0:63] = '{
   32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
   32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
   32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
   32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
   32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
   32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
   32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
   32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

assign mem_clk = clk; 
enum logic [2:0] {IDLE=3'b000, READ0=3'b001, READ1=3'b010, READ2=3'b011, READ3= 3'b100, COMP=3'b101, WRITE=3'b110} state;
logic [31:0] a,b,c,d,e,f,g,h,temp,wt;
logic [31:0] w[16], H[8]; //w array (Creates 16 bit multiplexor)
logic [31:0] t, t2;
logic [15:0] wc, rc;
//logic [31:0] s0, s1;

// Functions
function logic [31:0] rightrotate(input logic [31:0] x, input logic [7:0] r);
  rightrotate = (x >> r) | (x << (32-r));
endfunction 

function logic [255:0] sha256_op(input logic [31:0] a,b,c,d,e,f,g,h,w,k);
  logic [31:0] s0,s1,ch,maj,t1,t2; //internal signals
  s0 = rightrotate(a,2)^rightrotate(a,13)^rightrotate(a,22);
  maj = (a&b)^(a&c)^(b&c);
  t2 = maj + s0;
  s1 = rightrotate(e,6)^rightrotate(e,11)^rightrotate(e,25);
  ch = (e&f)^((~e)&g);
  t1 = ch+s1+h+k+w;
  
  // NOTE: "a" and "e are dependent on themselves.
  // a=t1+t2 -> t2=maj+S0 -> maj=(a&b), S0=rightrotate(a,2)
  sha256_op = {t1+t2,a,b,c,d+t1,e,f,g};
endfunction

function logic [31:0] wtnew; //no inputs
  logic [31:0] s0, s1;
  s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
  s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
  wtnew = w[0]+s0+w[9]+s1;

  // Left rotate w array and update w[15]
  // Changes "scanning" area of w without needing a 64-bit multiplexor
  
endfunction 

always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    state <= IDLE;
  end
  else begin
    case (state)
      IDLE: begin
        if (start) begin // READ first word
			    mem_we <= 0;
          //mem_addr <= message_addr;
          //Initialize counters
          rc <= 0; //word counter
          wc <= 0;
          t <= 0; // counter for w for COMP
			    t2 <= 0; // counter for w for read words from message
			    //t3 <= 0; // counter for w to WRITE

          // Initialize Message Digests (H0-7) to 32-bit constants
          H[0] <= 32'h6a09e667;
          H[1] <= 32'hbb67ae85;
          H[2] <= 32'h3c6ef372;
          H[3] <= 32'ha54ff53a;
          H[4] <= 32'h510e527f;
          H[5] <= 32'h9b05688c;
          H[6] <= 32'h1f83d9ab;
          H[7] <= 32'h5be0cd19;
          state <= READ0;
        end
      end
      READ0: begin
        mem_we <= 0; // Read address
        mem_addr <= message_addr + rc; //Read (t2)th word from message
        rc <= rc + 1; //Updatemto read next word
        state <= READ1;
      end
      READ1: begin // Buffer State to update current word for next cycle
        state <= READ2;
        mem_addr <= message_addr + rc; //Read (t2)th word from message
        rc <= rc + 1;
         //Updatemto read next word
      end
      READ2: begin // Add words from message 
        //$display("rc: %d",rc);
        w[t2] <= mem_read_data; // Add word from M to w array
        t2 <= t2 + 1;	// Update w array index
        state <= READ3;
      end
      READ3: begin
        w[t2] <= mem_read_data; // Add word from M to w array
        	// Update w array index
        if (rc == 20) begin // If all words read, go to COMP
          state <= COMP;
          // Added Padded words to w array
          for (int i = 4; i < 16; i++) begin
            if (i == 4) begin
              w[i] <= 32'h80000000;
            end
            else if (i == 15) begin
              w[i] <= 32'd640;
            end
            else begin
              w[i] <= 32'h00000000;
            end
          end
          wt <= w[0]; //Get w[0] for next cycle
          {a, b, c, d, e, f, g, h} <= {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};
          t <= t + 1; //Update counter for next COMP cycle
          //rc <= 0; // reset counter to indicate that all words are read
        end
        else if (rc == 16) begin // Begin COMP
          state <= COMP;
          t2 <= 0; //Reset counter for second block
			    wt <= w[0];
          t <= t + 1;
          {a, b, c, d, e, f, g, h} <= {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};
        end
        else begin
          state <= READ0;
          t2 <= t2 + 1;
        end
        //Read tth word of the message
        //NOTE: "w" takes two cycles to update
      end

      COMP: begin //Process the Message
        //$display("state: %d, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, k: %h",t-1,a,b,c,d,e,f,g,h,wt,k[t-1]);
        //$display("a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h",a,b,c,d,e,f,g,h);
        //$display("h0: %h, h1: %h, h2: %h, h3: %h, h4: %h, h5: %h, h6: %h, h7: %h",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);

        if (t < 65) begin
          //state <= COMP;
          if (t < 16) begin
            wt <= w[t];
          end
          else begin
            wt <= wtnew;
            for (int i = 0; i<15;i++) begin
              w[i] <= w[i+1];
            end
            w[15] <= wtnew;
          end
          {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wt, k[t-1]);

          t <= t + 1;
        end
        else begin 
          {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]} <= {H[0]+a, H[1]+b, H[2]+c, H[3]+d, H[4]+e, H[5]+f, H[6]+g, H[7]+h};
          if (rc == 20) begin //Write once both blocks are processed
            state <= WRITE;
          end
          else begin
            state <= READ0;
            t <= 0;
            //rc <= 16;
          end
        end
      end

      WRITE: begin
        mem_we <= 1;
        if (wc < 8) begin
          mem_addr <= output_addr + wc;
          mem_write_data <= H[wc];
          wc <= wc + 1;
        end
        else begin
          //mem_we <= 0;
          state <= IDLE;
          done <= 1;
        end
      end
  endcase
  end
end
endmodule   
