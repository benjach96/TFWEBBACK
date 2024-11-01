namespace TrackingSystem.Backend.Entities
{
    public class ErrorSimple
    {
        public int Codigo { get; set; }
        public string Mensaje { get; set; }
        public ErrorSimple(int codigo, string mensaje)
        {
            Codigo = codigo;
            Mensaje = mensaje;
        }
    }
}
