const request = require('supertest');
const app = require('../server');

// Mock pentru Supabase Client
jest.mock('@supabase/supabase-js', () => {
  return {
    createClient: jest.fn(() => ({
      auth: {
        getUser: jest.fn((token) => {
          if (token === 'token_valid') {
            return Promise.resolve({ data: { user: { id: 'user_123', email: 'test@example.com' } }, error: null });
          }
          return Promise.resolve({ data: { user: null }, error: new Error('Token invalid') });
        })
      }
    }))
  };
});

// Mock pentru Google Generative AI
jest.mock('@google/generative-ai', () => {
  return {
    GoogleGenerativeAI: jest.fn().mockImplementation(() => {
      return {
        getGenerativeModel: jest.fn().mockImplementation(() => {
          return {
            generateContent: jest.fn().mockResolvedValue({
              response: {
                text: jest.fn().mockReturnValue(JSON.stringify({
                  caloriiTinta: 2200,
                  proteineTinta: 160
                }))
              }
            })
          };
        })
      };
    })
  };
});

describe('Backend API Tests', () => {
  describe('GET /health', () => {
    it('ar trebui să returneze status ok', async () => {
      const res = await request(app).get('/health');
      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('ok');
      expect(res.body).toHaveProperty('timestamp');
    });
  });

  describe('Autentificare middleware requireAuth', () => {
    it('ar trebui să blocheze cererea cu 401 dacă lipsește header-ul de autorizare', async () => {
      const res = await request(app).post('/api/chat').send({ mesaj: 'Bună' });
      expect(res.statusCode).toBe(401);
      expect(res.body.eroare).toContain('Token lipsă');
    });

    it('ar trebui să blocheze cererea cu 401 dacă token-ul este invalid', async () => {
      const res = await request(app)
        .post('/api/chat')
        .set('Authorization', 'Bearer token_invalid')
        .send({ mesaj: 'Bună' });
      expect(res.statusCode).toBe(401);
      expect(res.body.eroare).toContain('Token invalid');
    });

    it('ar trebui să permită accesul cu token valid', async () => {
      const res = await request(app)
        .post('/api/chat')
        .set('Authorization', 'Bearer token_valid')
        .send({ mesaj: 'Bună' });
      
      expect(res.statusCode).not.toBe(401);
    });
  });

  describe('Validări input /api/calculeaza-profil', () => {
    it('ar trebui să returneze 400 dacă lipsesc date', async () => {
      const res = await request(app)
        .post('/api/calculeaza-profil')
        .set('Authorization', 'Bearer token_valid')
        .send({ varsta: 25 });
      expect(res.statusCode).toBe(400);
      expect(res.body.eroare).toContain('Date incomplete');
    });

    it('ar trebui să returneze 400 dacă vârsta este invalidă', async () => {
      const res = await request(app)
        .post('/api/calculeaza-profil')
        .set('Authorization', 'Bearer token_valid')
        .send({ varsta: 5, greutate: 70, inaltime: 170, sex: 'Masculin', activitate: 'Sedentar', obiectiv: 'Slăbire' });
      expect(res.statusCode).toBe(400);
      expect(res.body.eroare).toContain('Vârsta trebuie să fie');
    });

    it('ar trebui să returneze 400 dacă sexul este invalid', async () => {
      const res = await request(app)
        .post('/api/calculeaza-profil')
        .set('Authorization', 'Bearer token_valid')
        .send({ varsta: 25, greutate: 70, inaltime: 170, sex: 'Altul', activitate: 'Sedentar', obiectiv: 'Slăbire' });
      expect(res.statusCode).toBe(400);
      expect(res.body.eroare).toContain('Sexul selectat este invalid');
    });
  });
});
